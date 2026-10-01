/* ═════════════════════════════════════════════════════════════════
   SUPERFILE — Universal Digital Object Platform  (UI controller)
   Vanilla JS.  All requests go to the local API (offline-first).
   ═════════════════════════════════════════════════════════════════ */
"use strict";

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => [...document.querySelectorAll(sel)];

const state = {
  current: null,      // object detail payload
  registry: null,
  tab: "view",
};

/* ── helpers ─────────────────────────────────────────────────── */
function fmtBytes(n) {
  if (n == null) return "—";
  if (n < 1024) return n + " B";
  if (n < 1048576) return (n / 1024).toFixed(1) + " KB";
  return (n / 1048576).toFixed(2) + " MB";
}
function status(msg) { $("#status").textContent = msg; }
function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}
async function api(path, opts = {}) {
  const res = await fetch(path, opts);
  const ct = res.headers.get("content-type") || "";
  if (!ct.includes("application/json")) {
    if (!res.ok) throw new Error("HTTP " + res.status);
    return res;
  }
  const body = await res.json();
  if (!res.ok || body.ok === false) throw new Error(body.error || "HTTP " + res.status);
  return body;
}
function supportClass(level) {
  if (level.startsWith("FULL")) return "full";
  if (level.startsWith("PARTIAL")) return "partial";
  if (level.startsWith("INSPECTION")) return "inspection";
  return "unsupported";
}

/* ── navigation ──────────────────────────────────────────────── */
function switchTab(name) {
  state.tab = name;
  $$(".tab").forEach((t) => t.classList.toggle("active", t.dataset.tab === name));
  $$(".tab-pane").forEach((p) => p.classList.toggle("active", p.id === "tab-" + name));
  renderTab(name);
}
function renderTab(name) {
  const pane = $("#tab-" + name);
  if (!pane) return;
  const renderers = {
    view: renderView, edit: renderEdit, inspect: renderInspect,
    transform: renderTransform, export: renderExport, history: renderHistory,
    graph: renderGraph, registry: renderRegistry, explorer: renderExplorer,
    matrix: renderMatrix, demo: renderDemo, about: renderAbout,
    encrypt: renderEncrypt, decrypt: renderDecrypt,
  };
  (renderers[name] || (() => {}))(pane);
}

/* ── object loading ──────────────────────────────────────────── */
async function loadObject(id) {
  status("loading object…");
  const body = await api("/api/object/" + encodeURIComponent(id));
  state.current = body.detail;
  renderObjectHeader();
  renderSidebar();
  switchTab("view");
  status("loaded " + (state.current.original_filename || state.current.detected_format));
}

function renderObjectHeader() {
  const d = state.current;
  if (!d) { $("#object-header").classList.add("hidden"); return; }
  $("#object-header").classList.remove("hidden");
  $("#oh-name").textContent = d.original_filename || "(unnamed " + d.detected_format + ")";
  const badge = $("#oh-support");
  badge.textContent = d.support_level;
  badge.className = "badge " + supportClass(d.support_level);
  $("#oh-type").textContent = d.object_type;
  $("#oh-format").textContent =
    `${d.detected_format}  (${d.mime || "?"})`;
  $("#oh-mime").textContent = d.mime || "—";
  $("#oh-size").textContent = fmtBytes(d.size);
  $("#oh-hash").textContent = d.checksum || "—";
  const det = (d.metadata && d.metadata.detection) || {};
  $("#oh-detect").textContent =
    `${det.display || d.detected_format} — confidence ${(det.confidence ?? 0) * 100 | 0}% via ${det.method || "?"}` +
    (det.notes ? ` (${det.notes})` : "");
  $("#oh-caps").innerHTML = (d.capabilities || []).map((c) =>
    `<span class="cap">${esc(c)}</span>`).join("");
  const w = $("#oh-warnings");
  if (d.warnings && d.warnings.length) {
    w.classList.remove("hidden");
    w.innerHTML = "⚠ SAFETY / PARSING WARNINGS<ul>" +
      d.warnings.map((x) => `<li>${esc(x)}</li>`).join("") + "</ul>";
  } else w.classList.add("hidden");
}

function renderSidebar() {
  // recents
  api("/api/recent").then((r) => {
    const ul = $("#recent-list");
    if (!r.recent.length) { ul.innerHTML = `<li class="muted">empty</li>`; return; }
    ul.innerHTML = r.recent.map((it) => `
      <li class="rec-item" data-id="${esc(it.object_id)}">
        <div class="rec-name">${esc(it.original_filename || it.detected_format)}</div>
        <div class="rec-meta">${esc(it.detected_format)} · ${fmtBytes(it.size)} · ${esc(it.support_level)}</div>
      </li>`).join("");
    $$("#recent-list .rec-item").forEach((li) =>
      li.addEventListener("click", () => loadObject(li.dataset.id)));
  }).catch(() => {});
  // object tree
  const tree = $("#object-tree");
  const d = state.current;
  if (!d) { tree.innerHTML = `<p class="muted">no object loaded</p>`; return; }
  tree.innerHTML = treeNodeHtml(d, true);
  $$("#object-tree [data-id]").forEach((el) =>
    el.addEventListener("click", (e) => { e.stopPropagation(); loadObject(el.dataset.id); }));
}
function treeNodeHtml(node, open) {
  const label = `${esc(node.original_filename || node.detected_format || "object")} ` +
    `<span class="muted">[${esc(node.object_type || node.type || "?")}]</span>`;
  const kids = node.children || [];
  if (!kids.length) return `<div class="leaf" data-id="${esc(node.object_id)}">${label}</div>`;
  return `<details ${open ? "open" : ""}><summary data-id="${esc(node.object_id)}">${label}</summary>` +
    kids.map((c) => treeNodeHtml(c)).join("") + `</details>`;
}

/* ═══════════ VIEW TAB (format-aware viewers) ═══════════ */
function renderView(pane) {
  const d = state.current;
  if (!d) { pane.innerHTML = $("#welcome").outerHTML; bindWelcome(); return; }
  const kind = (d.content && d.content.kind) || "";
  const mediaUrl = `/api/object/${encodeURIComponent(d.object_id)}/media`;
  const blobUrl = (ref) =>
    `/api/object/${encodeURIComponent(d.object_id)}/blob/${encodeURIComponent(ref["__blob__"] || "")}`;
  let html = "";

  if (kind === "text" || kind === "source") {
    html = `<pre class="code">${esc(d.content.text || "")}</pre>`;
  } else if (kind === "structured") {
    html = `<div class="row" style="margin-bottom:8px">
        <button class="act" id="v-raw">RAW TEXT</button>
        <button class="act" id="v-tree">STRUCTURE TREE</button></div>
      <div id="v-raw-box"><pre class="code">${esc(d.content.raw ?? d.content.text ?? "")}</pre></div>
      <div id="v-tree-box" class="jsontree hidden">${treeValue(d.content.data, "root")}</div>`;
  } else if (kind === "table") {
    const cols = d.content.columns || [];
    const rows = (d.content.rows || []).slice(0, 200);
    html = `<p class="muted">${d.content.row_count} rows × ${cols.length} columns (delimiter ${
      JSON.stringify(d.content.delimiter)})</p><div style="overflow:auto"><table class="data"><thead><tr>` +
      cols.map((c) => `<th>${esc(c)}</th>`).join("") + `</tr></thead><tbody>` +
      rows.map((r) => "<tr>" + cols.map((_, i) => `<td>${esc(r[i] ?? "")}</td>`).join("") + "</tr>").join("") +
      `</tbody></table></div>`;
    } else if (kind === "image") {
    if (d.content.decoded === false) {
      html = `<div class="panel"><b>INSPECTION ONLY</b><p class="muted">${esc(d.content.note || "")}</p>
        <p class="muted">Original bytes are preserved — open the INSPECT tab or export via .sfp.</p>
        <div class="img-stage"><img alt="original bytes" src="${mediaUrl}"></div></div>`;
    } else if (d.content.pixels) {
      html = `<div class="row" style="margin-bottom:8px">
          <button class="act" id="im-zoom-in">ZOOM +</button>
          <button class="act" id="im-zoom-out">ZOOM −</button>
          <button class="act" id="im-rot90">ROTATE 90° (LOSSLESS)</button>
          <span class="muted" id="im-zoom-label">${d.content.width}×${d.content.height}</span>
          <a class="act" href="${blobUrl(d.content.pixels)}" download="pixels.rgba">RAW RGBA</a>
          <a class="act" href="${blobUrl(d.content.pixels)}.png" download="image.png">PNG</a>
        </div>
        <div class="img-stage"><img id="im-img" alt="decoded image"
          src="${blobUrl(d.content.pixels)}.png" data-w="${d.content.width}" data-h="${d.content.height}"
          style="width:${Math.min(512, d.content.width * 2)}px"></div>
        <p class="muted" style="margin-top:6px">Showing the decoded pixel model; original ${
          esc(d.detected_format.toUpperCase())} bytes preserved for lossless re-export.</p>`;
    } else {
      html = `<div class="img-stage"><img alt="image" src="${mediaUrl}"></div>`;
    }
  } else if (kind === "vector") {
    html = `<div class="img-stage">${d.content.text ?
      d.content.text.replace(/<script[\s\S]*?<\/script>/gi, "") : ""}</div>
      <p class="muted">SVG rendered structurally (scripts stripped). Element counts: ${
        esc(JSON.stringify(d.content.element_counts || {}))}</p>`;
  } else if (kind === "animation") {
    const frames = d.content.frames || [];
    html = `<div class="row" style="margin-bottom:8px"><span class="muted">${
      d.content.frame_count} frames · loop ${d.content.loop} · ${d.content.width}×${d.content.height}</span></div>
      <div class="img-stage"><img alt="animation" src="${mediaUrl}"></div>
      <h3 class="section-title">FRAMES (click to extract as child object)</h3>
      <div class="frame-strip">` +
      frames.map((f) => `<div class="frame" data-idx="${f.index}">
        <img src="${blobUrl(f.pixels)}.png" alt="frame ${f.index}">#${f.index}<br>${f.delay_ms}ms</div>`).join("") +
      `</div>`;
  } else if (kind === "audio") {
    html = `<audio controls preload="metadata" src="${mediaUrl}"></audio>
      <h3 class="section-title">WAVEFORM</h3>
      <canvas class="wave-canvas" id="wave"></canvas>
      <h3 class="section-title">STREAM</h3>
      <div class="kv">
        <label>CODEC</label><span>${esc(d.content.format || d.content.codec || "?")}</span>
        <label>SAMPLE RATE</label><span>${esc(d.content.sample_rate ?? "?")} Hz</span>
        <label>CHANNELS</label><span>${esc(d.content.channels ?? "?")}</span>
        <label>DURATION</label><span>${esc(d.content.duration ?? "?")} s</span>
        <label>BITRATE</label><span>${esc(d.content.bitrate_kbps ?? "—")}</span>
      </div>`;
  } else if (kind === "video") {
    const playable = ["mp4", "webm", "mov"].includes(d.detected_format);
    html = (playable
        ? `<video id="vid" controls preload="metadata" src="${mediaUrl}"></video>
           <div class="row"><button class="act" id="v-cap">EXTRACT FRAME (RENDERED)</button>
           <span class="muted">browser decodes container if a codec is available</span></div>`
        : `<div class="panel"><b>INSPECTION ONLY</b><p class="muted">No browser-playable codec path
           for ${esc(d.detected_format)} — metadata below. Original bytes preserved.</p></div>`) +
      `<h3 class="section-title">TRACKS</h3><table class="data"><thead><tr>
        <th>TYPE</th><th>CODEC</th><th>W×H</th><th>DURATION</th><th>SAMPLES</th></tr></thead><tbody>` +
      (d.content.tracks || []).map((t) => `<tr><td>${esc(t.type)}</td><td>${esc(t.codec || "?")}</td>
        <td>${t.width ? t.width + "×" + t.height : "—"}</td>
        <td>${esc(t.duration_sec ?? "?")}</td><td>${esc(t.sample_count ?? "—")}</td></tr>`).join("") +
      `</tbody></table>`;
  } else if (kind === "document") {
    if (d.detected_format === "pdf") {
      html = `<embed class="pdf-embed" type="application/pdf" src="${mediaUrl}">
        <h3 class="section-title">EXTRACTED TEXT</h3><pre class="code">${esc(d.content.raw_text || "(none)")}</pre>`;
    } else {
      html = `<div class="kv">
          <label>PARAGRAPHS / CHAPTERS</label><span>${
            d.content.paragraph_count ?? (d.content.chapters || []).length ?? 0}</span>
          <label>PROPERTIES</label><span class="mono">${esc(JSON.stringify(
            d.content.core_properties || d.content.metadata || {}))}</span>
        </div><h3 class="section-title">TEXT</h3>
        <pre class="code">${esc(d.content.raw_text || "")}</pre>`;
    }
  } else if (kind === "archive") {
    const entries = d.content.entries || [];
    html = `<div class="kv">
        <label>ENTRIES</label><span>${d.content.entry_count ?? entries.length}</span>
        <label>TOTAL UNCOMPRESSED</label><span>${fmtBytes(d.content.total_uncompressed)}</span>
      </div>
      <div class="row" style="margin:8px 0"><button class="act" id="a-extract">EXTRACT ALL → CHILD OBJECTS</button></div>
      <table class="data"><thead><tr><th>PATH</th><th>SIZE</th><th>PACKED</th><th>EXTRA</th></tr></thead><tbody>` +
      entries.slice(0, 500).map((e) => `<tr><td>${e.is_dir ? "📁 " : ""}${esc(e.path)}</td>
        <td>${fmtBytes(e.size)}</td><td>${e.compressed_size != null ? fmtBytes(e.compressed_size) : "—"}</td>
        <td class="mono">${esc(JSON.stringify({ ...e, path: 0, size: 0, compressed_size: 0, is_dir: 0 })
          .replace(/[{}",:0]/g, "").trim() || "—")}</td></tr>`).join("") +
      `</tbody></table>`;
  } else if (kind === "binary") {
    html = `<div class="row"><b>STATIC INSPECTION ONLY — NEVER EXECUTED</b></div>
      <pre class="code">${esc(d.content.hex_preview || "")}</pre>`;
  } else if (kind === "mesh") {
    html = `<div class="row" style="margin-bottom:8px">
        <button class="act" id="m-spin">SPIN ON/OFF</button>
        <span class="muted">wireframe preview · ${esc(d.content.vertices ?? 0)} verts · ${
          esc(d.content.faces ?? "?")} faces</span></div>
      <div class="img-stage"><canvas id="mesh-canvas" width="640" height="420"></canvas></div>`;
  } else if (kind === "database") {
    const schema = d.content.schema || [];
    html = `<div class="kv"><label>PAGE SIZE</label><span>${esc(d.content.page_size ?? "?")}</span>
        <label>ENCODING</label><span>${esc(d.content.text_encoding ?? "?")}</span>
        <label>TABLES</label><span>${esc(d.content.table_count ?? schema.length)}</span></div>
      ` + schema.map((t) => `<div class="panel">
        <h4 class="mono">${t.type === "table" ? "▦" : "☰"} ${esc(t.name)}
          ${t.row_count != null ? `<span class="muted">(${t.row_count} rows)</span>` : ""}</h4>
        <pre class="code">${esc(t.sql || "")}</pre>
        ${t.sample_rows ? `<table class="data"><thead><tr>${
          Object.keys(t.sample_rows[0] || {}).map((k) => `<th>${esc(k)}</th>`).join("")
        }</tr></thead><tbody>${
          t.sample_rows.map((r) => "<tr>" + Object.values(r).map((v) =>
            `<td>${esc(v)}</td>`).join("") + "</tr>").join("")
        }</tbody></table>` : ""}</div>`).join("");
  } else if (kind === "project") {
    html = `<div class="panel"><h3>${esc(d.content.title || "SUPERFILE Project")}</h3>
      <p class="muted">${esc(d.content.note || "")}</p></div>
      <p class="muted">Use the GRAPH tab to walk the full object graph. SAVE AS .SFP stores everything losslessly.</p>`;
  } else {
    html = `<pre class="code">${esc(JSON.stringify(d.content, null, 2).slice(0, 20000))}</pre>`;
  }
  pane.innerHTML = html;
  bindViewers(pane, d);
}

function bindViewers(pane, d) {
  const mediaUrl = `/api/object/${encodeURIComponent(d.object_id)}/media`;
  const blobUrl = (ref) =>
    `/api/object/${encodeURIComponent(d.object_id)}/blob/${encodeURIComponent(ref["__blob__"] || "")}`;
  // structured toggle
  if ($("#v-raw", pane)) {
    $("#v-raw", pane).onclick = () => {
      $("#v-raw-box", pane).classList.remove("hidden");
      $("#v-tree-box", pane).classList.add("hidden");
    };
    $("#v-tree", pane).onclick = () => {
      $("#v-raw-box", pane).classList.add("hidden");
      $("#v-tree-box", pane).classList.remove("hidden");
    };
  }
  // image zoom/rotate
  const img = $("#im-img", pane);
  if (img) {
    let zoom = 2, rot = 0;
    const apply = () => {
      img.style.width = (img.dataset.w * zoom) + "px";
      img.style.transform = `rotate(${rot}deg)`;
      $("#im-zoom-label", pane).textContent =
        `${img.dataset.w}×${img.dataset.h} · zoom ${zoom}× · rot ${rot}°`;
    };
    $("#im-zoom-in", pane).onclick = () => { zoom = Math.min(16, zoom * 2); apply(); };
    $("#im-zoom-out", pane).onclick = () => { zoom = Math.max(0.25, zoom / 2); apply(); };
    $("#im-rot90", pane).onclick = () => {
      rot = (rot + 90) % 360; apply();
      // lossless server-side rotate for export accuracy
      api(`/api/object/${encodeURIComponent(d.object_id)}/transform`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ transform: "image.rotate", params: { degrees: 90 } }),
      }).then(() => { status("rotated 90° (lossless, recorded in history)"); })
        .catch((e) => status("rotate failed: " + e.message));
    };
  }
  // waveform
  const wave = $("#wave", pane);
  if (wave && d.content.peaks) drawWaveform(wave, d.content.peaks);
  // gif frames -> extract
  pane.querySelectorAll(".frame").forEach((fr) => {
    fr.addEventListener("click", async () => {
      try {
        await api(`/api/object/${encodeURIComponent(d.object_id)}/transform`, {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ transform: "gif.extract_frame", params: { index: +fr.dataset.idx } }),
        });
        status(`extracted frame ${fr.dataset.idx} as child object`);
        loadObject(d.object_id);
      } catch (e) { status("frame extract failed: " + e.message); }
    });
  });
  // archive extract
  const ax = $("#a-extract", pane);
  if (ax) ax.addEventListener("click", async () => {
    try {
      await api(`/api/object/${encodeURIComponent(d.object_id)}/transform`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ transform: "archive.extract_all", params: { limit: 200 } }),
      });
      status("extracted archive entries as child objects");
      loadObject(d.object_id);
    } catch (e) { status("extract failed: " + e.message); }
  });
  // video frame capture (RENDERED)
  const cap = $("#v-cap", pane);
  if (cap) cap.addEventListener("click", async () => {
    const v = $("#vid", pane);
    const cv = document.createElement("canvas");
    cv.width = v.videoWidth || 320; cv.height = v.videoHeight || 240;
    cv.getContext("2d").drawImage(v, 0, 0);
    const blob = await new Promise((r) => cv.toBlob(r, "image/png"));
    const b64 = await blob.arrayBuffer().then((b) =>
      btoa(String.fromCharCode(...new Uint8Array(b))));
    await api(`/api/object/${encodeURIComponent(d.object_id)}/add_child`, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ filename: `frame_${(v.currentTime | 0)}s.png`, data_b64: b64 }),
    });
    status("frame captured via browser render → child object (RENDERED)");
    loadObject(d.object_id);
  });
  // mesh preview
  const mesh = $("#mesh-canvas", pane);
  if (mesh && d.content.preview_positions) initMeshPreview(mesh, d.content.preview_positions);
}

function drawWaveform(cv, peaks) {
  const ctx = cv.getContext("2d");
  const w = cv.width = cv.clientWidth * (window.devicePixelRatio || 1);
  const h = cv.height = 90 * (window.devicePixelRatio || 1);
  ctx.fillStyle = "#0a0f18"; ctx.fillRect(0, 0, w, h);
  ctx.strokeStyle = "#38bdf8"; ctx.lineWidth = 1;
  ctx.beginPath();
  const n = peaks.length;
  for (let i = 0; i < n; i++) {
    const x = (i / n) * w;
    const a = Math.max(1, peaks[i] * (h / 2 - 4));
    ctx.moveTo(x, h / 2 - a); ctx.lineTo(x, h / 2 + a);
  }
  ctx.stroke();
}

function initMeshPreview(canvas, positions) {
  const ctx = canvas.getContext("2d");
  let angle = 0.6, spin = true;
  const btn = $("#m-spin");
  if (btn) btn.onclick = () => { spin = !spin; };
  const pts = [];
  for (let i = 0; i < positions.length; i += 3)
    pts.push([positions[i], positions[i + 1], positions[i + 2]]);
  const draw = () => {
    ctx.fillStyle = "#0a0f18"; ctx.fillRect(0, 0, canvas.width, canvas.height);
    const s = 60, cx = canvas.width / 2, cy = canvas.height / 2;
    const ca = Math.cos(angle), sa = Math.sin(angle);
    ctx.fillStyle = "#38bdf8";
    for (const [x, y, z] of pts) {
      const xr = x * ca - z * sa, zr = x * sa + z * ca;
      const px = cx + xr * s, py = cy - y * s;
      const depth = 0.5 + zr / 4;
      ctx.globalAlpha = Math.max(0.2, Math.min(1, depth));
      ctx.fillRect(px, py, 2.5, 2.5);
    }
    ctx.globalAlpha = 1;
    if (spin) angle += 0.02;
    requestAnimationFrame(draw);
  };
  draw();
}

function treeValue(v, key, depth = 0) {
  const k = `<span class="j-key">${esc(key)}</span>: `;
  if (v === null) return `<div>${k}<span class="j-null">null</span></div>`;
  if (typeof v === "object") {
    const entries = Array.isArray(v)
      ? v.map((x, i) => [i, x]) : Object.entries(v);
    if (!entries.length) return `<div>${k}${Array.isArray(v) ? "[]" : "{}"}</div>`;
    return `<details ${depth < 1 ? "open" : ""}><summary>${k}${
      Array.isArray(v) ? `[${v.length}]` : `{${entries.length}}`}</summary>` +
      entries.map(([kk, vv]) => treeValue(vv, kk, depth + 1)).join("") + `</details>`;
  }
  const cls = typeof v === "string" ? "j-str" : typeof v === "number" ? "j-num" : "j-bool";
  const shown = typeof v === "string" ? JSON.stringify(v) : String(v);
  return `<div>${k}<span class="${cls}">${esc(shown)}</span></div>`;
}

/* ═══════════ EDIT TAB ═══════════ */
function renderEdit(pane) {
  const d = state.current;
  if (!d) { pane.innerHTML = `<p class="muted">open an object first</p>`; return; }
  const caps = d.capabilities || [];
  const editable = caps.includes("edit") || caps.includes("encode");
  const isTextual = ["text", "source", "structured", "vector"].includes(
    (d.content && d.content.kind) || "");
  if (isTextual && editable) {
    const text = d.content.raw ?? d.content.text ?? "";
    pane.innerHTML = `
      <p class="muted">Edits update the object's working representation. The
        <b>original bytes stay preserved</b> (lossless-preservation principle) and the edit is
        recorded in HISTORY.</p>
      <textarea class="editor" id="edit-area">${esc(text)}</textarea>
      <div class="row" style="margin-top:8px">
        <button class="act accent" id="edit-apply">APPLY EDIT</button>
        <span class="muted" id="edit-msg"></span>
      </div>`;
    $("#edit-apply", pane).onclick = async () => {
      try {
        const body = await api(`/api/object/${encodeURIComponent(d.object_id)}/edit`, {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ op: "set_text", params: { text: $("#edit-area", pane).value } }),
        });
        state.current = body.detail;
        $("#edit-msg", pane).textContent = "applied ✓ (recorded in history)";
        status("edit applied");
      } catch (e) { $("#edit-msg", pane).textContent = "failed: " + e.message; }
    };
  } else if ((d.content && d.content.kind === "image") && d.content.pixels) {
    pane.innerHTML = `<p class="muted">Image pixel editing happens through the
      <b>TRANSFORM</b> tab (resize / crop / rotate / flip / grayscale) — each op is recorded
      in object history.</p>
      <button class="act" onclick="switchTab('transform')">GO TO TRANSFORM →</button>`;
  } else {
    pane.innerHTML = `<div class="panel"><b>NO DIRECT EDITOR</b>
      <p class="muted">${esc(d.detected_format)} is <b>${esc(d.support_level)}</b>${
        d.support_level.startsWith("INSPECTION") ? " — static inspection only." : "."}</p>
      <p class="muted">You can still inspect, transform where supported, and export via
        .sfp or the listed targets.</p></div>`;
  }
}

/* ═══════════ INSPECT TAB (universal inspector) ═══════════ */
async function renderInspect(pane) {
  const d = state.current;
  if (!d) { pane.innerHTML = `<p class="muted">open an object first</p>`; return; }
  pane.innerHTML = `<p class="muted">loading universal inspector…</p>`;
  let rep;
  try {
    const body = await api(`/api/object/${encodeURIComponent(d.object_id)}/inspect`);
    rep = body.inspect;
  } catch (e) { pane.innerHTML = `<p class="muted">inspect failed: ${esc(e.message)}</p>`; return; }
  const sec = (title, content) =>
    `<h3 class="section-title">${title}</h3><div class="panel">${content}</div>`;
  const kv = (obj, skip = []) =>
    `<div class="kv">${Object.entries(obj || {})
      .filter(([k, v]) => !skip.includes(k) && typeof v !== "object")
      .map(([k, v]) => `<label>${esc(k.toUpperCase())}</label><span>${esc(v)}</span>`).join("")}</div>`;
  pane.innerHTML =
    sec("GENERAL", kv(rep.general, ["children", "warnings", "relationships",
        "transformations", "adapter_manifest", "hash", "size"]) +
      `<div class="kv">
        <label>SIZE</label><span>${fmtBytes(rep.general.size)}</span>
        <label>HASH (SHA-256)</label><span class="mono">${esc(rep.general.hash)}</span>
        <label>ORIGINAL BYTES</label><span>${rep.general.original_bytes_preserved
          ? "✓ preserved (lossless)" : "—"}</span>
        <label>OBJECT ID</label><span class="mono">${esc(rep.general.object_id)}</span>
      </div>` +
      (rep.general.children && rep.general.children.length
        ? `<h4 style="margin-top:10px">CHILDREN</h4><table class="data"><thead><tr>
            <th>NAME</th><th>TYPE</th><th>FORMAT</th><th>SIZE</th></tr></thead><tbody>` +
          rep.general.children.map((c) => `<tr><td>${esc(c.original_filename)}</td>
            <td>${esc(c.object_type)}</td><td>${esc(c.detected_format)}</td>
            <td>${fmtBytes(c.size)}</td></tr>`).join("") + "</tbody></table>" : "")) +
    sec("STRUCTURE",
        Object.keys(rep.structure || {}).length
          ? `<pre class="code">${esc(JSON.stringify(rep.structure, null, 2).slice(0, 30000))}</pre>`
          : `<p class="muted">no structure info</p>`) +
    sec("FORMAT", kv(rep.format, ["capabilities", "adapter_manifest", "render", "note"]) +
      `<div class="kv"><label>CAPABILITIES</label><span>${
        (rep.format.capabilities || []).map((c) => `<span class="cap">${esc(c)}</span>`).join(" ")}</span>
        ${rep.format.render ? `<label>RENDER</label><span>${esc(rep.format.render)}</span>` : ""}
        ${rep.format.note ? `<label>NOTE</label><span>${esc(rep.format.note)}</span>` : ""}</div>`);
}

/* ═══════════ TRANSFORM TAB ═══════════ */
async function renderTransform(pane) {
  const d = state.current;
  if (!d) { pane.innerHTML = `<p class="muted">open an object first</p>`; return; }
  const body = await api(`/api/object/${encodeURIComponent(d.object_id)}/transforms`);
  const list = body.transforms;
  if (!list.length) {
    pane.innerHTML = `<div class="panel"><b>NO TRANSFORMS REGISTERED</b>
      <p class="muted">Nothing is registered for ${esc(d.detected_format)} /
        ${esc(d.object_type)}. (Truthful matrix — no fake operations.)</p></div>`;
    return;
  }
  pane.innerHTML = `<p class="muted">Universal Transform Engine — every operation is
    classified (<b>LOSSLESS / LOSSY / STRUCTURAL / RENDERED / RECONSTRUCTED</b>) and recorded
    in object history.</p>` +
    list.map((t) => `
      <div class="panel" data-tid="${esc(t.id)}">
        <div class="row">
          <h4 style="margin:0;flex:1">${esc(t.label)}</h4>
          <span class="kind-tag ${esc(t.kind)}">${esc(t.kind)}</span>
        </div>
        <p class="muted">${esc(t.description || "")}</p>
        <div class="row">
          ${(t.params || []).map((p) =>
            `<label class="muted">${esc(p.name)}
              <input type="${p.type === "int" ? "number" : "text"}" data-p="${esc(p.name)}"
                value="${esc(p.default ?? "")}" ${p.min != null ? `min="${p.min}"` : ""}
                ${p.max != null ? `max="${p.max}"` : ""}></label>`).join("")}
          <button class="act accent t-run">RUN</button>
          <span class="muted t-msg"></span>
        </div>
      </div>`).join("");
  pane.querySelectorAll(".panel[data-tid]").forEach((card) => {
    card.querySelector(".t-run").onclick = async () => {
      const params = {};
      card.querySelectorAll("[data-p]").forEach((inp) => {
        params[inp.dataset.p] = inp.type === "number" ? +inp.value : inp.value;
      });
      try {
        const r = await api(`/api/object/${encodeURIComponent(d.object_id)}/transform`, {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ transform: card.dataset.tid, params }),
        });
        state.current = r.detail;
        card.querySelector(".t-msg").textContent = "✓ done";
        status("transform applied: " + card.dataset.tid);
        renderObjectHeader();
      } catch (e) {
        card.querySelector(".t-msg").textContent = "✗ " + e.message;
      }
    };
  });
}

/* ═══════════ EXPORT TAB (conversion matrix — only real targets) ═══════════ */
function renderExport(pane) {
  const d = state.current;
  if (!d) { pane.innerHTML = `<p class="muted">open an object first</p>`; return; }
  const opts = d.export_formats || [];
  pane.innerHTML = `
    <p class="muted">EXPORT AS — only formats this object can <b>genuinely</b> produce.
      Each conversion states its honesty class. (.sfp is always lossless.)</p>
    <div class="export-grid">` +
    opts.map((o) => `
      <div class="export-card">
        <h4>${esc(o.label)}</h4>
        <span class="kind-tag ${esc(o.kind)}">${esc(o.kind)}</span>
        <p>${esc(o.notes || "")}</p>
        <button class="act accent x-go" data-fmt="${esc(o.format)}">EXPORT</button>
      </div>`).join("") + `</div>
    <h3 class="section-title">SAVE AS SUPERFILE CONTAINER</h3>
    <div class="panel"><p class="muted">The .sfp container stores the complete UniversalObject
      graph — metadata, content, children, history, relationships and the original bytes —
      with a SHA-256 integrity checksum. It is the only fully lossless target.</p>
      <button class="act accent x-go" data-fmt="sfp">SAVE .SFP</button></div>`;
  pane.querySelectorAll(".x-go").forEach((btn) => {
    btn.addEventListener("click", async () => {
      try {
        status("exporting…");
        const res = await fetch(`/api/object/${encodeURIComponent(d.object_id)}/export`, {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ format: btn.dataset.fmt, raw: true }),
        });
        if (!res.ok) throw new Error((await res.json()).error || res.status);
        const blob = await res.blob();
        const cd = res.headers.get("content-disposition") || "";
        const name = /filename="([^"]+)"/.exec(cd)?.[1] || `export.${btn.dataset.fmt}`;
        const a = document.createElement("a");
        a.href = URL.createObjectURL(blob);
        a.download = name;
        a.click();
        URL.revokeObjectURL(a.href);
        status("exported " + name);
        loadObject(d.object_id); // refresh history
      } catch (e) { status("export failed: " + e.message); }
    });
  });
}

/* ═══════════ HISTORY TAB ═══════════ */
function renderHistory(pane) {
  const d = state.current;
  if (!d) { pane.innerHTML = `<p class="muted">open an object first</p>`; return; }
  const hist = d.transformations || [];
  pane.innerHTML = `<h3 class="section-title">TRANSFORMATION HISTORY</h3>
    <table class="data"><thead><tr><th>#</th><th>ACTION</th><th>DETAIL</th><th>KIND</th><th>TIME</th>
    </tr></thead><tbody>` +
    hist.map((t) => `<tr><td>${t.step}</td><td class="mono">${esc(t.action)}</td>
      <td>${esc(t.detail || "")}</td><td><span class="kind-tag ${esc(t.kind)}">${esc(t.kind)}</span></td>
      <td class="muted">${new Date(t.timestamp * 1000).toLocaleTimeString()}</td></tr>`).join("") +
    `</tbody></table>
    <p class="muted" style="margin-top:10px">History lives inside the object and is preserved
      in the .sfp container.</p>`;
}

/* ═══════════ GRAPH TAB ═══════════ */
function renderGraph(pane) {
  const d = state.current;
  if (!d) { pane.innerHTML = `<p class="muted">open an object first</p>`; return; }
  pane.innerHTML = `<h3 class="section-title">OBJECT GRAPH (nesting is first-class)</h3>
    <div class="panel"><div class="tree">${treeNodeHtml(d, true)}</div></div>
    <h3 class="section-title">RELATIONSHIPS</h3>
    <table class="data"><thead><tr><th>RELATION</th><th>TARGET</th><th>NOTE</th></tr></thead><tbody>` +
    (d.relationships || []).map((r) => `<tr><td>${esc(r.relation)}</td>
      <td class="mono">${esc((r.target_id || "").slice(0, 12))}…</td><td>${esc(r.note || "")}</td></tr>`).join("") +
    `</tbody></table>`;
  pane.querySelectorAll("[data-id]").forEach((el) =>
    el.addEventListener("click", (e) => { e.stopPropagation(); loadObject(el.dataset.id); }));
}

/* ═══════════ REGISTRY TAB (format support database) ═══════════ */
async function renderRegistry(pane) {
  if (!state.registry) {
    pane.innerHTML = `<p class="muted">loading format registry…</p>`;
    state.registry = await api("/api/registry");
  }
  const reg = state.registry;
  pane.innerHTML = `
    <h3 class="section-title">FORMAT SUPPORT DATABASE
      <input type="text" id="fmt-filter" class="wide" style="width:240px;float:right"
        placeholder="filter formats…"></h3>
    <table class="data" id="fmt-table"><thead><tr>
      <th>FORMAT</th><th>EXTENSION</th><th>CATEGORY</th><th>MIME</th>
      <th>READ</th><th>CREATE</th><th>EDIT</th><th>EXPORT</th><th>DETECTION</th><th>SUPPORT LEVEL</th>
    </tr></thead><tbody>` +
    reg.formats.map((f) => `<tr data-s="${esc((f.format + f.extension + f.category + f.mime).toLowerCase())}">
      <td><b>${esc(f.format)}</b></td><td class="mono">${esc(f.extension)}</td>
      <td>${esc(f.category)}</td><td class="mono">${esc(f.mime)}</td>
      <td class="${f.read ? "ok-yes" : "ok-no"}">${f.read ? "✓" : "—"}</td>
      <td class="${f.create ? "ok-yes" : "ok-no"}">${f.create ? "✓" : "—"}</td>
      <td class="${f.edit ? "ok-yes" : "ok-no"}">${f.edit ? "✓" : "—"}</td>
      <td class="${f.export ? "ok-yes" : "ok-no"}">${f.export ? "✓" : "—"}</td>
      <td class="muted">${esc(f.detection)}</td>
      <td class="lvl-${f.support.split(" ")[0]}">${esc(f.support)}</td>
    </tr>`).join("") + `</tbody></table>
    <p class="muted">FULL = read+create+edit+export · PARTIAL = read/parse + some edit/export ·
      INSPECTION ONLY = safe static analysis · formats outside this table are preserved as raw bytes.</p>
    <h3 class="section-title">ADAPTER MANIFESTS (plugin API)</h3>` +
    reg.adapters.map((a) => `<div class="panel">
      <h4>${esc(a.name)} <span class="muted">v${esc(a.version)}${
        a.is_example ? ' · <span style="color:var(--purple)">EXAMPLE ADAPTER</span>' : ""}</span></h4>
      <div class="kv">
        <label>FORMATS</label><span class="mono">${esc(a.formats.join(", "))}</span>
        <label>INPUT TYPES</label><span class="mono">${esc(a.input_types.join(", "))}</span>
        <label>OUTPUT TYPES</label><span class="mono">${esc(a.output_types.join(", "))}</span>
      </div>
      <details><summary class="muted">capabilities per format</summary>
        <pre class="code">${esc(JSON.stringify(a.capabilities, null, 2))}</pre></details>
    </div>`).join("");
  $("#fmt-filter", pane).addEventListener("input", (e) => {
    const q = e.target.value.toLowerCase();
    pane.querySelectorAll("#fmt-table tbody tr").forEach((tr) =>
      tr.style.display = tr.dataset.s.includes(q) ? "" : "none");
  });
}

/* ═══════════ PROTOCOL EXPLORER TAB ═══════════ */
async function renderExplorer(pane) {
  const d = state.current;
  pane.innerHTML = `
    <h3 class="section-title">PROTOCOL PIPELINE — the internal representation is inspectable</h3>
    <p class="muted">Every import follows the SUPERFILE superprotocol:</p>`;
  let stages = null;
  if (d) {
    try {
      const body = await api(`/api/object/${encodeURIComponent(d.object_id)}/pipeline`);
      stages = body.pipeline;
    } catch (e) { /* fall through to schematic */ }
  }
  const schematic = [
    ["FILE", "any digital object on disk"],
    ["FORMAT DETECTION", "magic bytes / signatures / structure — never just the extension"],
    ["FORMAT ADAPTER", "adapter.read() → parse() → decode()  (capabilities advertised)"],
    ["UNIVERSAL OBJECT", "one object model: metadata, content, original_bytes, checksum"],
    ["OBJECT GRAPH", "children + relationships (streams, entries, pages, project members)"],
    ["TRANSFORMATION", "recorded, classified ops: LOSSLESS / LOSSY / STRUCTURAL / RENDERED / RECONSTRUCTED"],
    ["EXPORT ADAPTER", "adapter.export() — only real conversions are offered"],
    ["TARGET FILE", "standard format out, or .sfp SUPERFILE container (lossless)"],
  ];
  const rows = (stages || schematic.map(([s, x]) => ({ stage: s, title: s, detail: x, data: null })));
  pane.innerHTML += rows.map((s, i) => `
    <div class="pipe-stage">
      <div class="pipe-badge">${i + 1}. ${esc(s.stage)}</div>
      <div style="flex:1">
        <h4>${esc(s.title || "")}</h4>
        <div class="muted">${esc(s.detail || "")}</div>
        ${s.data ? `<details><summary class="muted">inspect stage data</summary>
          <pre>${esc(JSON.stringify(s.data, null, 2).slice(0, 8000))}</pre></details>` : ""}
      </div>
    </div>
    ${i < rows.length - 1 ? `<div class="pipe-arrow">↓</div>` : ""}`).join("");
  if (!stages) pane.innerHTML += `<p class="muted">Open an object to see live stage values.</p>`;
}

/* ═══════════ MATRIX TAB ═══════════ */
async function renderMatrix(pane) {
  if (!state.registry) state.registry = await api("/api/registry");
  const m = state.registry.conversion_matrix || {};
  pane.innerHTML = `
    <h3 class="section-title">CONVERSION CAPABILITY MATRIX
      <input type="text" id="mx-filter" style="width:220px;float:right"
        placeholder="filter…"></h3>
    <p class="muted">Rows list every supported source format and its <b>actually supported</b>
      export targets. Impossible conversions are simply absent. Conversion kinds:
      <span class="kind-tag LOSSLESS">LOSSLESS</span>
      <span class="kind-tag LOSSY">LOSSY</span>
      <span class="kind-tag STRUCTURAL">STRUCTURAL</span>
      <span class="kind-tag RENDERED">RENDERED</span>
      <span class="kind-tag RECONSTRUCTED">RECONSTRUCTED</span></p>
    <table class="data" id="mx-table"><thead><tr><th>SOURCE</th><th>EXPORT TARGETS</th></tr></thead><tbody>` +
    Object.entries(m).filter(([k]) => k !== "_errors").map(([src, opts]) => `
      <tr data-s="${esc(src.toLowerCase())}">
        <td><b>${esc(src)}</b></td>
        <td>${opts.length
          ? opts.map((o) => `<span class="kind-tag ${esc(o.kind)}" title="${esc(o.notes || "")}">${
              esc(o.format)}</span>`).join(" ")
          : `<span class="muted">.sfp container only (bytes preserved)</span>`}</td>
      </tr>`).join("") + `</tbody></table>`;
  $("#mx-filter", pane).addEventListener("input", (e) => {
    const q = e.target.value.toLowerCase();
    pane.querySelectorAll("#mx-table tbody tr").forEach((tr) =>
      tr.style.display = tr.dataset.s.includes(q) ? "" : "none");
  });
}

/* ═══════════ DEMO TAB ═══════════ */
async function renderDemo(pane) {
  pane.innerHTML = `<p class="muted">loading samples…</p>`;
  let list = { samples: [] };
  try { list = await api("/api/demo/list"); } catch (e) { /* empty */ }
  pane.innerHTML = `
    <h3 class="section-title">DEMONSTRATION — generated sample files</h3>
    <p class="muted">Small, generated samples covering the format families. The full loop:
      <b>IMPORT → DETECT → PARSE → UNIVERSAL OBJECT → INSPECT → MODIFY → EXPORT</b>.</p>
    <div class="row">
      <button class="act accent" id="demo-load">LOAD ALL INTO RECENT</button>
      <button class="act" id="demo-gen">GENERATE SAMPLE FILES</button>
      <span class="muted">demo dir: ${esc(list.demo_dir || "demo/")}</span>
    </div>
    <table class="data"><thead><tr><th>FILE</th><th>SIZE</th><th>NOTE</th></tr></thead><tbody>` +
    (list.samples || []).map((s) => `<tr>
      <td><a class="dl" href="#" data-path="${esc(s.path)}">${esc(s.name)}</a></td>
      <td>${fmtBytes(s.size)}</td><td class="muted">${esc(s.note || "")}</td></tr>`).join("") +
    `</tbody></table>`;
  $("#demo-load", pane).onclick = async () => {
    status("loading demo set…");
    const r = await api("/api/demo/load", { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" });
    status(`loaded ${r.loaded.length} sample objects`);
    renderSidebar();
  };
  $("#demo-gen", pane).onclick = async () => {
    const r = await api("/api/demo/generate", { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" });
    status(`generated ${r.created.length} sample files`);
    renderDemo(pane);
  };
  pane.querySelectorAll("[data-path]").forEach((a) =>
    a.addEventListener("click", async (e) => {
      e.preventDefault();
      const r = await api("/api/import_path", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ path: a.dataset.path }),
      });
      loadObject(r.object.object_id);
    }));
}

/* ═══════════ ABOUT TAB ═══════════ */
function renderAbout(pane) {
  pane.innerHTML = `
    <h3 class="section-title">ABOUT SUPERFILE</h3>
    <div class="panel">
      <p><b>SUPERFILE</b> — Universal Digital Object Protocol v1.0</p>
      <p class="muted">"One application. One object model. Many formats."</p>
      <p>Different digital file formats are represented as interoperable
        <b>UniversalObjects</b> through a common protocol while retaining their native
        representations and format-specific capabilities.</p>
    </div>
    <h3 class="section-title">SECURITY MODEL</h3>
    <div class="panel">
      <ul>
        <li>Imported files are <b>untrusted data</b>; nothing is ever auto-executed.</li>
        <li>EXE / DLL / ELF / WASM / scripts: <b>static inspection only</b>.</li>
        <li>Archive paths are sanitised (no traversal, no symlinks); decompression is capped
          (ratio + absolute limits).</li>
        <li>Declared sizes are validated; signatures are checked; SHA-256 hashes are computed.</li>
        <li>Parsers run with strict limits (pixels, depth, entries, text size).</li>
        <li>Suspicious binaries raise visible warnings (W+X sections, TLS callbacks, rpath…).</li>
        <li>SQLite databases open read-only &amp; immutable; no extension loading.</li>
        <li>Offline-first: no network, no cloud, no API keys.</li>
      </ul>
    </div>
    <h3 class="section-title">CONVERSION SEMANTICS</h3>
    <div class="panel">
      <p><span class="kind-tag LOSSLESS">LOSSLESS</span> identical information
        (re-encode/container) ·
        <span class="kind-tag LOSSY">LOSSY</span> information discarded ·
        <span class="kind-tag STRUCTURAL">STRUCTURAL</span> structural re-representation ·
        <span class="kind-tag RENDERED">RENDERED</span> produced by rendering ·
        <span class="kind-tag RECONSTRUCTED">RECONSTRUCTED</span> rebuilt from a model</p>
    </div>
    <h3 class="section-title">ARCHITECTURE</h3>
    <div class="panel">
      <p class="mono">PROTOCOL · OBJECT MODEL · ADAPTERS · APPLICATION UI — separated.
        A new format = a new adapter; the protocol never changes.</p>
    </div>`;
}

/* ═══════════ toolbar wiring ═══════════ */
function bindWelcome() {
  const wo = $("#w-open"); if (wo) wo.onclick = () => $("#file-input").click();
  const wc = $("#w-create"); if (wc) wc.onclick = () => showCreateMenu();
  const wd = $("#w-demo"); if (wd) wd.onclick = () => switchTab("demo");
}

function showCreateMenu() {
  const menu = $("#create-menu");
  if (!state.registry) {
    api("/api/registry").then((r) => { state.registry = r; showCreateMenu(); });
    return;
  }
  menu.innerHTML = "";
  state.registry.creators.forEach((c) => {
    const b = document.createElement("button");
    b.innerHTML = `${esc(c.label)}<span class="menu-note">${esc(c.formats.join(" · "))}</span>`;
    b.onclick = async () => {
      menu.classList.add("hidden");
      status("creating " + c.id + "…");
      try {
        const r = await api("/api/create", {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ kind: c.id, params: {} }),
        });
        await loadObject(r.object.object_id);
      } catch (e) { status("create failed: " + e.message); }
    };
    menu.appendChild(b);
  });
  menu.classList.toggle("hidden");
}

async function init() {
  bindWelcome();
  $$(".tab").forEach((t) => t.addEventListener("click", () => switchTab(t.dataset.tab)));
  $$("#sidebar a[data-tab]").forEach((a) =>
    a.addEventListener("click", (e) => { e.preventDefault(); switchTab(a.dataset.tab); }));

  $("#btn-open").onclick = () => $("#file-input").click();
  $("#file-input").addEventListener("change", async (e) => {
    const f = e.target.files[0];
    if (!f) return;
    status("importing " + f.name + "…");
    try {
      const buf = await f.arrayBuffer();
      const res = await fetch("/api/import", {
        method: "POST",
        headers: { "Content-Type": "application/octet-stream", "X-Filename": f.name },
        body: buf,
      });
      const body = await res.json();
      if (!body.ok) throw new Error(body.error);
      await loadObject(body.object.object_id);
    } catch (err) { status("import failed: " + err.message); }
    e.target.value = "";
  });

  $("#btn-import-path").onclick = async () => {
    const path = prompt("Filesystem path to import (server-side, untrusted):");
    if (!path) return;
    try {
      const r = await api("/api/import_path", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ path }),
      });
      await loadObject(r.object.object_id);
    } catch (e) { status("import failed: " + e.message); }
  };

  $("#btn-create").onclick = (e) => { e.stopPropagation(); showCreateMenu(); };
  document.addEventListener("click", (e) => {
    if (!e.target.closest(".tool-wrap")) $("#create-menu").classList.add("hidden");
  });

  $("#btn-save-sfp").onclick = () => doExport("sfp");
  $("#btn-export").onclick = () => switchTab("export");
  $("#btn-inspect").onclick = () => switchTab("inspect");
  $("#btn-edit").onclick = () => switchTab("edit");
  $("#btn-transform").onclick = () => switchTab("transform");
  $("#btn-encrypt").onclick = () => switchTab("encrypt");
  $("#btn-decrypt").onclick = () => switchTab("decrypt");

  async function doExport(fmt) {
    const d = state.current;
    if (!d) { status("open an object first"); return; }
    try {
      const res = await fetch(`/api/object/${encodeURIComponent(d.object_id)}/export`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ format: fmt, raw: true }),
      });
      if (!res.ok) throw new Error((await res.json()).error || res.status);
      const blob = await res.blob();
      const cd = res.headers.get("content-disposition") || "";
      const name = /filename="([^"]+)"/.exec(cd)?.[1] || `export.${fmt}`;
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob); a.download = name; a.click();
      URL.revokeObjectURL(a.href);
      status("saved " + name);
    } catch (e) { status("export failed: " + e.message); }
  }

  try {
    state.registry = await api("/api/registry");
    $("#status-right").textContent =
      `${state.registry.formats.length} formats · ${state.registry.adapters.length} adapters`;
  } catch (e) { status("registry load failed: " + e.message); }
  renderSidebar();
  renderAbout($("#tab-about"));
  status("ready — open a file, create an object, or run the demo");
}

window.switchTab = switchTab;  // used by inline handlers
document.addEventListener("DOMContentLoaded", init);

/* ═══════════ layout toggles — collapsible top chrome + sidebar ═══════════
   UI-only and additive: nothing above this block is modified.
     #sf-top-toggle   collapses #titlebar + #toolbar together (the thin strip stays)
     #sf-side-toggle  collapses #sidebar to width 0 (the slim edge rail stays)
   State = classes on <html> (sf-top-collapsed / sf-side-collapsed), persisted in
   localStorage (sf_top_collapsed / sf_sidebar_collapsed = "1" | "0"); every storage
   access is wrapped in try/catch (index.html <head> holds a 6-line copy of the restore step so the
   first paint is already correct).  Collapsed elements are hidden, never removed or
   re-rendered, so lists, inspector data and scroll positions survive collapse → expand. */
(function layoutToggles() {
  const KEY_TOP = "sf_top_collapsed", KEY_SIDE = "sf_sidebar_collapsed";
  const DUR = 200, EASE = "ease";                       // keep in sync with the .2s in app.css
  const root = document.documentElement;
  const topBtn = document.getElementById("sf-top-toggle");
  const sideBtn = document.getElementById("sf-side-toggle");
  const sidebar = document.getElementById("sidebar");
  const bars = [document.getElementById("titlebar"), document.getElementById("toolbar")];
  if (!topBtn || !sideBtn || !sidebar || bars.some((b) => !b)) return;   // markup missing → do nothing

  const store = {
    get(k) { try { return window.localStorage.getItem(k) === "1"; } catch (e) { return false; } },
    set(k, on) { try { window.localStorage.setItem(k, on ? "1" : "0"); } catch (e) { /* blocked → session only */ } },
  };
  const reduced = () => {
    try { return window.matchMedia("(prefers-reduced-motion: reduce)").matches; } catch (e) { return false; }
  };
  const label = (btn, collapsed, what) => {
    const t = (collapsed ? "Expand " : "Collapse ") + what;
    btn.setAttribute("aria-expanded", collapsed ? "false" : "true");
    btn.setAttribute("aria-label", t);
    btn.title = t;
  };

  let topOn = store.get(KEY_TOP), sideOn = store.get(KEY_SIDE);
  let topAnims = [], topSeq = 0, sideTimer = 0, ready = false;

  /* ── top chrome: #titlebar + #toolbar animate as ONE unit (same clock, same duration) ── */
  const PROPS = ["height", "paddingTop", "paddingBottom", "borderBottomWidth", "opacity"];
  const ZERO = { height: "0px", paddingTop: "0px", paddingBottom: "0px", borderBottomWidth: "0px", opacity: "0" };
  const snap = (el) => { const cs = getComputedStyle(el), o = {}; PROPS.forEach((p) => { o[p] = cs[p]; }); return o; };

  function setTop(collapsed, animate) {
    const seq = ++topSeq;
    const hidden = root.classList.contains("sf-top-collapsed");
    const from = bars.map((el) => (hidden ? ZERO : snap(el)));    // where the bars are right now (mid-animation too)
    topAnims.forEach((a) => a.cancel()); topAnims = [];
    bars.forEach((el) => { el.style.overflow = ""; });
    topOn = collapsed;
    label(topBtn, collapsed, "top bar (title bar + toolbar)");
    store.set(KEY_TOP, collapsed);
    if (!animate || !ready || reduced() || typeof bars[0].animate !== "function") {
      root.classList.toggle("sf-top-collapsed", collapsed);
      return;
    }
    if (!collapsed) root.classList.remove("sf-top-collapsed");     // lay both bars out at natural size first
    const to = bars.map((el) => (collapsed ? ZERO : snap(el)));
    bars.forEach((el, i) => {
      el.style.overflow = "hidden";
      topAnims.push(el.animate([from[i], to[i]],
        { duration: DUR, easing: EASE, fill: collapsed ? "forwards" : "none" }));
    });
    Promise.all(topAnims.map((a) => a.finished)).then(() => {
      if (seq !== topSeq) return;                                  // superseded by a newer click
      if (collapsed) root.classList.add("sf-top-collapsed");       // bars leave the layout once fully folded
      bars.forEach((el) => { el.style.overflow = ""; });
      topAnims.forEach((a) => a.cancel()); topAnims = [];
    }).catch(() => { /* cancelled by a newer toggle */ });
  }

  /* ── sidebar: width/padding/border transition lives in CSS; JS only marks the animation window ── */
  function endSideAnim() { clearTimeout(sideTimer); root.classList.remove("sf-side-anim"); }

  function setSide(collapsed, animate) {
    sideOn = collapsed;
    label(sideBtn, collapsed, "sidebar");
    store.set(KEY_SIDE, collapsed);
    if (animate && ready && !reduced()) {
      if (!root.classList.contains("sf-side-collapsed")) {         // remember the real inner width → no text re-wrap mid-slide
        const cs = getComputedStyle(sidebar);
        const inner = sidebar.clientWidth - parseFloat(cs.paddingLeft) - parseFloat(cs.paddingRight);
        if (inner > 0) root.style.setProperty("--sf-side-inner", inner + "px");
      }
      root.classList.add("sf-side-anim");
      clearTimeout(sideTimer);
      sideTimer = setTimeout(endSideAnim, DUR + 80);
    } else endSideAnim();
    root.classList.toggle("sf-side-collapsed", collapsed);
  }
  sidebar.addEventListener("transitionend", (e) => {
    if (e.target === sidebar && e.propertyName === "width") endSideAnim();
  });

  /* ── restore the persisted layout BEFORE first paint, transitions still off ── */
  label(topBtn, topOn, "top bar (title bar + toolbar)");
  label(sideBtn, sideOn, "sidebar");
  root.classList.toggle("sf-top-collapsed", topOn);
  root.classList.toggle("sf-side-collapsed", sideOn);
  void root.offsetWidth;                  // commit that state un-animated …
  root.classList.add("sf-anim");          // … then enable transitions for user-driven changes only
  ready = true;

  topBtn.addEventListener("click", () => setTop(!topOn, true));
  sideBtn.addEventListener("click", () => setSide(!sideOn, true));
})();

/* ═══════════ file-details slide — #object-header keeps its row, slides the rest ═══════════
   UI-only and additive: renderObjectHeader()'s "hidden" logic is untouched and the two states
   compose correctly — with no file loaded the whole block stays hidden whatever the user's
   collapse preference is; once a file is loaded the preference decides.
   The .oh-row (filename + badge) always stays visible; only #sf-oh-details (grid, capabilities,
   warnings) slides.  State = class sf-oh-collapsed on <html>, persisted in localStorage
   (sf_objheader_collapsed = "1" | "0", every access in try/catch); index.html <head> restores it
   before the first paint.  The details are never removed or re-rendered, so the data and the
   scroll position of #tab-body survive. */
(function objectHeaderSlide() {
  const KEY = "sf_objheader_collapsed";
  const DUR = 200;                                  // keep in sync with the .2s in app.css
  const root = document.documentElement;
  const header = document.getElementById("object-header");
  const details = document.getElementById("sf-oh-details");
  const btn = document.getElementById("sf-oh-toggle");
  if (!header || !details || !btn) return;          // markup missing → do nothing

  const store = {
    get() { try { return window.localStorage.getItem(KEY) === "1"; } catch (e) { return false; } },
    set(on) { try { window.localStorage.setItem(KEY, on ? "1" : "0"); } catch (e) { /* blocked → session only */ } },
  };
  const reduced = () => {
    try { return window.matchMedia("(prefers-reduced-motion: reduce)").matches; } catch (e) { return false; }
  };
  function label(collapsed) {
    const t = collapsed ? "Expand file details" : "Collapse file details";
    btn.setAttribute("aria-expanded", collapsed ? "false" : "true");
    btn.setAttribute("aria-label", t);
    btn.title = t;
  }

  let on = store.get(), seq = 0, timer = 0, ready = false;

  function clearInline() { details.style.maxHeight = ""; details.style.opacity = ""; }
  function currentPx() {                            // where the slide is right now (mid-animation included)
    const v = parseFloat(getComputedStyle(details).maxHeight);
    return isFinite(v) ? v : details.scrollHeight;
  }

  function setState(collapsed, animate) {
    on = collapsed;
    store.set(collapsed);
    label(collapsed);
    details.setAttribute("aria-hidden", collapsed ? "true" : "false");
    if (!animate || !ready || reduced() || header.classList.contains("hidden")) {
      clearTimeout(timer); seq++;                   // no animation (restore, reduced motion, block hidden) → snap
      clearInline();
      root.classList.toggle("sf-oh-collapsed", collapsed);
      return;
    }
    const mySeq = ++seq;
    clearTimeout(timer);
    const from = currentPx();
    const fromOpacity = getComputedStyle(details).opacity;
    root.classList.remove("sf-oh-collapsed");        // always animate from a laid-out element
    details.style.maxHeight = from + "px";
    details.style.opacity = fromOpacity;
    void details.offsetHeight;                       // commit the start values (single forced reflow)
    const to = collapsed ? 0 : details.scrollHeight; // scrollHeight is the full content height even when clamped
    details.style.maxHeight = to + "px";
    details.style.opacity = collapsed ? "0" : "1";
    const done = () => {
      clearTimeout(timer);
      details.removeEventListener("transitionend", onEnd);
      if (mySeq !== seq) return;                     // superseded by a newer click
      clearInline();
      root.classList.toggle("sf-oh-collapsed", collapsed);
    };
    const onEnd = (e) => { if (e.target === details && e.propertyName === "max-height") done(); };
    details.addEventListener("transitionend", onEnd);
    timer = setTimeout(done, DUR + 140);             // fallback (transitionend can be skipped)
  }

  /* ── restore the persisted state before the first user interaction ── */
  label(on);
  details.setAttribute("aria-hidden", on ? "true" : "false");
  root.classList.toggle("sf-oh-collapsed", on);
  clearInline();
  ready = true;

  btn.addEventListener("click", () => setState(!on, true));
})();
/* ═══════════ ENCRYPT / DECRYPT tabs — AES-256-GCM container encryption ═══════════
   UI-only additions on top of the existing app; the ENCRYPT tab works on the
   currently loaded object exactly like EXPORT does, the DECRYPT tab works on any
   .sfp from disk and hands the unlocked object to the EXISTING open flow
   (loadObject) so the user lands in the normal VIEW tab. */
function encDeviceLock() {
  return !!(state.registry && state.registry.device_lock);
}
function encDeviceNote() {
  return `<p class="enc-note">device-lock mode is Windows-only in this build — ` +
         `use a password, or open the file on the Windows build.</p>`;
}
async function encDownload(res, fallbackName) {
  if (!res.ok) {
    let msg = "HTTP " + res.status;
    try { const j = await res.json(); if (j && j.error) msg = j.error; } catch (e) { /* not JSON */ }
    throw new Error(msg);
  }
  const blob = await res.blob();
  const cd = res.headers.get("content-disposition") || "";
  const name = /filename="([^"]+)"/.exec(cd)?.[1] || fallbackName;
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob); a.download = name; a.click();
  URL.revokeObjectURL(a.href);
  return { name, bytes: blob.size };
}

function renderEncrypt(pane) {
  const d = state.current;
  if (!d) { pane.innerHTML = `<p class="muted">open an object first</p>`; return; }
  const lockable = encDeviceLock();
  const label = d.original_filename || d.detected_format;
  pane.innerHTML = `
    <div class="enc-wrap">
      <h3 class="section-title">ENCRYPT &amp; SAVE .SFP — AES-256-GCM</h3>
      <div class="panel">
        <p class="muted" style="margin-top:0">Encrypt <b>${esc(label)}</b>
          (${esc(d.detected_format)}, ${fmtBytes(d.size)}) into a locked <b>.sfp</b>. The original bytes,
          the decoded content and any decoded blobs are encrypted together — the file holds no readable
          plaintext of your data.</p>
        <div class="enc-step">
          <label>PASSWORD PROTECT THIS FILE?</label>
          <div class="radio-row">
            <label><input type="radio" name="enc-mode" id="enc-mode-pw" value="password" checked> Yes — use a password</label>
            <label><input type="radio" name="enc-mode" id="enc-mode-dev" value="device" ${lockable ? "" : "disabled"}> No — lock to this device</label>
          </div>
          ${lockable ? "" : encDeviceNote()}
        </div>
        <div id="enc-pwblock">
          <div class="row">
            <input type="password" id="enc-pw1" placeholder="password" autocomplete="new-password">
            <input type="password" id="enc-pw2" placeholder="confirm password" autocomplete="new-password">
          </div>
          <p id="enc-pwerr" class="enc-err hidden"></p>
        </div>
        <div class="enc-warn" id="enc-warn">
          <b>There is no password recovery.</b> If you forget this password, this file cannot be
          decrypted by anyone, including you.
          <label class="enc-ack"><input type="checkbox" id="enc-ack">
            <span id="enc-ack-text">I understand — I have stored this password somewhere safe.</span></label>
        </div>
        <div id="enc-devblock" class="hidden">
          <p class="enc-note">No password — this file will only open on this computer.</p>
        </div>
        <div class="row" style="margin-top:12px">
          <button class="act accent" id="enc-go" disabled>ENCRYPT &amp; SAVE .SFP</button>
          <span id="enc-msg" class="muted"></span>
        </div>
      </div>
    </div>`;

  const pw1 = $("#enc-pw1", pane), pw2 = $("#enc-pw2", pane), ack = $("#enc-ack", pane);
  const go = $("#enc-go", pane), msg = $("#enc-msg", pane), err = $("#enc-pwerr", pane);
  const warn = $("#enc-warn", pane), pwblock = $("#enc-pwblock", pane), devblock = $("#enc-devblock", pane);
  const isPw = () => $("#enc-mode-pw", pane).checked;

  function refresh() {
    const pw = isPw();
    pwblock.classList.toggle("hidden", !pw);
    devblock.classList.toggle("hidden", pw);
    warn.classList.remove("hidden");     // the warning + acknowledgement gate BOTH modes
    $("#enc-ack-text", pane).textContent = pw
      ? "I understand — I have stored this password somewhere safe."
      : "I understand — this file will only open on this computer.";
    const mismatch = pw && pw1.value && pw2.value && pw1.value !== pw2.value;
    err.classList.toggle("hidden", !mismatch);
    if (mismatch) err.textContent = "the two passwords do not match — fix that before encrypting";
    const ready = pw ? (pw1.value.length > 0 && pw1.value === pw2.value && ack.checked)
                     : (lockable && $("#enc-mode-dev", pane).checked && ack.checked);
    go.disabled = !ready;
  }
  ["enc-pw1", "enc-pw2", "enc-ack", "enc-mode-pw", "enc-mode-dev"].forEach((id) =>
    $("#" + id, pane).addEventListener(id === "enc-ack" || id.startsWith("enc-mode") ? "change" : "input", refresh));
  refresh();

  go.onclick = async () => {
    const mode = isPw() ? "password" : "device";
    const password = isPw() ? pw1.value : undefined;
    go.disabled = true;
    msg.className = "muted"; msg.textContent = "encrypting…";
    status("encrypting " + label + "…");
    try {
      const res = await fetch(`/api/object/${encodeURIComponent(d.object_id)}/encrypt`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ mode, password }),
      });
      const out = await encDownload(res, "object.encrypted.sfp");
      msg.className = "enc-ok";
      msg.textContent = `Encrypted and saved as ${out.name} (${fmtBytes(out.bytes)})`;
      status(`encrypted (${mode} mode) → ${out.name}`);
    } catch (e) {
      msg.className = "enc-err";
      msg.textContent = "encryption failed: " + e.message;
      status("encryption failed: " + e.message);
    }
    refresh();
  };
}

function renderDecrypt(pane) {
  const lockable = encDeviceLock();
  pane.innerHTML = `
    <div class="enc-wrap">
      <h3 class="section-title">DECRYPT A .SFP — AES-256-GCM</h3>
      <div class="panel">
        <p class="muted" style="margin-top:0">Unlock an encrypted <b>.sfp</b> and open it in the normal
          viewer. Everything happens on this machine — nothing is sent anywhere.</p>
        <div class="row"><input type="file" id="dec-file" accept=".sfp,application/x-superfile"></div>
        <div class="enc-step">
          <label>ENTER A PASSWORD?</label>
          <div class="radio-row">
            <label><input type="radio" name="dec-mode" id="dec-mode-pw" value="password" checked> Yes — I have the password</label>
            <label><input type="radio" name="dec-mode" id="dec-mode-dev" value="device" ${lockable ? "" : "disabled"}> No — the file is locked to this device</label>
          </div>
          ${lockable ? "" : encDeviceNote()}
        </div>
        <div id="dec-pwblock"><input type="password" id="dec-pw" placeholder="password" autocomplete="current-password"></div>
        <div class="row" style="margin-top:12px">
          <button class="act accent" id="dec-go">DECRYPT</button>
          <span id="dec-msg" class="muted"></span>
        </div>
        <div id="dec-result"></div>
      </div>
    </div>`;

  const file = $("#dec-file", pane), pw = $("#dec-pw", pane), go = $("#dec-go", pane);
  const msg = $("#dec-msg", pane), result = $("#dec-result", pane), pwblock = $("#dec-pwblock", pane);
  const isPw = () => $("#dec-mode-pw", pane).checked;
  function refresh() { pwblock.classList.toggle("hidden", !isPw()); }
  ["dec-mode-pw", "dec-mode-dev"].forEach((id) => $("#" + id, pane).addEventListener("change", refresh));
  refresh();

  go.onclick = async () => {
    if (!file.files || !file.files[0]) {
      msg.className = "enc-err"; msg.textContent = "choose an encrypted .sfp file first";
      return;
    }
    result.innerHTML = "";                        // never leave a previous attempt's success block up
    const fd = new FormData();
    fd.append("file", file.files[0]);
    fd.append("mode", isPw() ? "password" : "device");
    fd.append("password", isPw() ? pw.value : "");
    msg.className = "muted"; msg.textContent = "decrypting…";
    status("decrypting " + file.files[0].name + "…");
    try {
      const r = await api("/api/decrypt", { method: "POST", body: fd });
      msg.className = "enc-ok"; msg.textContent = "decrypted " + r.filename;
      status(`decrypted ${r.original_filename || r.filename} (${fmtBytes(r.size)})`);
      result.innerHTML = `
        <div class="enc-result">
          <b>Decrypted and opened as an object.</b>
          <div class="enc-kv">${esc(r.original_filename || "(unnamed)")} · ${fmtBytes(r.size)}
            · saved as ${esc(r.filename)}</div>
          <div class="row" style="margin-top:8px">
            <button class="act accent" id="dec-open">OPEN THIS FILE</button>
          </div>
        </div>`;
      $("#dec-open", pane).onclick = () => loadObject(r.object_id);
    } catch (e) {
      msg.className = "enc-err"; msg.textContent = e.message;
      status("decrypt failed: " + e.message);
    }
  };
}

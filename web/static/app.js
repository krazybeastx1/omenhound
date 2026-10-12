"use strict";

// OmenHound UI — dependency-free force-directed graph on a canvas.
// No CDN: works fully offline and ships inside the Go binary.
//
// This file is the single front-end entry point. It is responsible for:
//   * hash-based routing (browser back/forward/refresh) across every view
//   * loading real data from the Go API and rendering it
//   * the canvas graph explorer (zoom/pan/fit/select/labels/legend/filters)
//   * the node/edge inspector and the object-detail modal
//   * search, filtering, sorting and pagination for the list views

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const COLORS = {
  User: "#00d4ff",
  Group: "#ff6b35",
  Computer: "#00ff88",
  Domain: "#b873ff",
  GPO: "#ff3d7f",
  OU: "#ffd600",
  Container: "#4ecdc4",
  Trust: "#ff8c42",
  Base: "#8b9ab8",
};

// Edge categories group BloodHound relationship types into a small, readable
// legend. Colors mirror the CSS --edge-* variables.
const EDGE_CATEGORIES = {
  containment: { label: "Containment", color: "#4a5a72", kinds: ["Contains", "GPLink", "MemberOf", "TrustedBy"] },
  acl: {
    label: "ACL / Rights",
    color: "#ffb84d",
    kinds: [
      "GenericAll", "GenericWrite", "WriteDacl", "WriteOwner", "Owns",
      "AllExtendedRights", "WriteSPN", "WriteAccountRestrictions", "WriteGPLink",
      "AddKeyCredentialLink", "AddAllowedToAct", "WriteAltSecurityIdentities",
      "AddMember", "AddSelf",
    ],
  },
  credential: {
    label: "Credential / DCSync",
    color: "#ff5c7a",
    kinds: [
      "DCSync", "GetChanges", "GetChangesAll", "GetChangesInFilteredSet",
      "ForceChangePassword", "ReadLAPSPassword", "ReadGMSAPassword", "DumpSMSAPassword",
    ],
  },
  remote: { label: "Remote / Session", color: "#b873ff", kinds: ["AdminTo", "HasSession", "CanRDP", "CanPSRemote", "ExecuteDCOM"] },
  delegation: { label: "Delegation", color: "#00ffc8", kinds: ["AllowedToDelegate", "AllowedToAct"] },
};
const EDGE_COLOR_DEFAULT = "#5c6b85";

const VIEWS = [
  "overview", "graph", "domains", "users", "groups", "computers", "ous",
  "gpos", "containers", "trusts", "relationships", "paths", "ingestion",
  "collection", "audit", "settings",
];

const DEFAULT_PREFS = {
  labels: true,
  edgeLabels: false,
  legend: true,
  physics: true,
  reduceMotion: false,
  autoRefresh: true,
  preserveSelection: true,
  refreshInterval: 0,
  theme: "dark",
  density: "comfortable",
};

// ---------------------------------------------------------------------------
// Element handles & graph state
// ---------------------------------------------------------------------------

const canvas = document.getElementById("graph");
const ctx = canvas ? canvas.getContext("2d") : null;

let nodes = [];
let edges = [];
let byId = new Map();
let alpha = 1;
let selectedNode = null;
let selectedEdge = null;

// view transform: screen = world * k + (x, y)
let view = { x: 0, y: 0, k: 1 };

const drag = { node: null, panning: false, moved: false, sx: 0, sy: 0, ox: 0, oy: 0 };

let prefs = { ...DEFAULT_PREFS };
let currentDomain = "";
let operatorToken = null;
let refreshTimer = null;
let statsCache = null;

const tableState = {};

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

function esc(s) {
  if (s === null || s === undefined) return "";
  return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}
const escapeHtml = esc;

function val(id) {
  const el = document.getElementById(id);
  return el ? String(el.value || "").trim() : "";
}

function flag(n, key) {
  return !!(n && n.props && (n.props[key] === "true" || n.props[key] === "True"));
}

function nodeLabel(n) {
  if (!n) return "—";
  return n.name || n.sam_account_name || n.id || "—";
}

function edgeColor(kind) {
  for (const key of Object.keys(EDGE_CATEGORIES)) {
    if (EDGE_CATEGORIES[key].kinds.indexOf(kind) !== -1) return EDGE_CATEGORIES[key].color;
  }
  return EDGE_COLOR_DEFAULT;
}

function edgeCategory(kind) {
  for (const key of Object.keys(EDGE_CATEGORIES)) {
    if (EDGE_CATEGORIES[key].kinds.indexOf(kind) !== -1) return key;
  }
  return "other";
}

async function apiGet(path) {
  const res = await fetch(path, { headers: { Accept: "application/json" } });
  let body = null;
  try { body = await res.json(); } catch (_) { /* non-JSON error page */ }
  if (!res.ok) {
    const msg = body && body.error ? body.error : `${res.status} ${res.statusText}`;
    throw new Error(msg);
  }
  return body;
}

function stateHTML(kind, title, detail) {
  if (kind === "loading") {
    return `<div class="state"><span class="spinner"></span><span>${esc(title || "Loading…")}</span></div>`;
  }
  if (kind === "error") {
    return `<div class="state error"><span class="state-title">⚠ ${esc(title || "Request failed")}</span>${detail ? `<span>${esc(detail)}</span>` : ""}</div>`;
  }
  return `<div class="state empty"><span class="state-title">${esc(title || "Nothing to show")}</span>${detail ? `<span>${esc(detail)}</span>` : ""}</div>`;
}

function toast(message, kind = "info") {
  const container = document.getElementById("toastContainer");
  if (!container) return;
  const icons = { success: "✓", error: "✕", warn: "⚠", info: "ℹ" };
  const el = document.createElement("div");
  el.className = "toast " + kind;
  el.innerHTML = `<span class="toast-icon">${icons[kind] || "ℹ"}</span><span class="toast-msg">${esc(message)}</span><button class="toast-close" aria-label="Dismiss">✕</button>`;
  const remove = () => { el.remove(); };
  el.querySelector(".toast-close").addEventListener("click", remove);
  container.appendChild(el);
  setTimeout(remove, 6000);
}

// ---------------------------------------------------------------------------
// Preferences (theme, density, graph rendering)
// ---------------------------------------------------------------------------

function loadPrefs() {
  let stored = {};
  try { stored = JSON.parse(localStorage.getItem("omenhound-settings") || "{}"); } catch (_) { stored = {}; }
  prefs = { ...DEFAULT_PREFS, ...stored };
  syncPrefsToControls();
  applyPrefs();
}

function savePrefs() {
  try { localStorage.setItem("omenhound-settings", JSON.stringify(prefs)); } catch (_) { /* storage disabled */ }
  syncPrefsToControls();
  applyPrefs();
  scheduleAutoRefresh();
}

function syncPrefsToControls() {
  const set = (id, v) => { const el = document.getElementById(id); if (el) el.checked = v; };
  const setVal = (id, v) => { const el = document.getElementById(id); if (el) el.value = v; };
  set("showLabels", prefs.labels);
  set("showEdgeLabels", prefs.edgeLabels);
  set("showLegend", prefs.legend);
  set("settingLabels", prefs.labels);
  set("settingEdgeLabels", prefs.edgeLabels);
  set("settingLegend", prefs.legend);
  set("settingPhysics", prefs.physics);
  set("settingReduceMotion", prefs.reduceMotion);
  set("settingAutoRefresh", prefs.autoRefresh);
  set("settingPreserveSelection", prefs.preserveSelection);
  setVal("settingRefreshInterval", prefs.refreshInterval || 0);
  setVal("settingTheme", prefs.theme);
  setVal("settingDensity", prefs.density);
}

function applyPrefs() {
  document.documentElement.setAttribute("data-theme", prefs.theme);
  document.body.classList.remove("density-compact", "density-comfortable", "density-spacious");
  document.body.classList.add("density-" + (prefs.density || "comfortable"));
  document.body.classList.toggle("reduce-motion", !!prefs.reduceMotion);
  const legendEl = document.getElementById("legend");
  if (legendEl) legendEl.classList.toggle("visible", !!prefs.legend && nodes.length > 0);
  draw();
}

function scheduleAutoRefresh() {
  if (refreshTimer) { clearInterval(refreshTimer); refreshTimer = null; }
  const secs = parseInt(prefs.refreshInterval, 10) || 0;
  if (secs > 0) refreshTimer = setInterval(() => { refresh().catch(() => {}); }, secs * 1000);
}

// ---------------------------------------------------------------------------
// Graph engine
// ---------------------------------------------------------------------------

function resize() {
  if (!canvas) return;
  const parent = canvas.parentElement;
  if (!parent) return;
  const r = parent.getBoundingClientRect();
  const dpr = window.devicePixelRatio || 1;
  canvas.width = Math.max(1, r.width * dpr);
  canvas.height = Math.max(1, r.height * dpr);
  canvas.style.width = r.width + "px";
  canvas.style.height = r.height + "px";
  if (ctx) ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
}
window.addEventListener("resize", resize);

function toScreen(p) {
  return { x: p.x * view.k + view.x, y: p.y * view.k + view.y };
}
function toWorld(sx, sy) {
  return { x: (sx - view.x) / view.k, y: (sy - view.y) / view.k };
}

function setGraphStatus(kind, title, detail) {
  const el = document.getElementById("graphStatus");
  if (!el) return;
  if (!kind) { el.hidden = true; el.innerHTML = ""; return; }
  el.hidden = false;
  el.innerHTML = stateHTML(kind, title, detail);
}

function nodeHidden(n) { return n.hidden === true; }

function edgeHidden(e) {
  const ek = val("edgeKindFilter");
  if (ek && e.kind !== ek) return true;
  const a = byId.get(e.source);
  const b = byId.get(e.target);
  if ((a && nodeHidden(a)) || (b && nodeHidden(b))) return true;
  return false;
}

function visibleNodes() { return nodes.filter((n) => !nodeHidden(n)); }

async function loadGraph() {
  setGraphStatus("loading", "Loading graph…");
  try {
    const g = await apiGet("/api/v1/graph");
    const rawNodes = g.nodes || [];
    const prevSelectedId = selectedNode ? selectedNode.id : null;
    const prevEdge = selectedEdge ? { source: selectedEdge.source, target: selectedEdge.target, kind: selectedEdge.kind } : null;

    const old = byId;
    nodes = rawNodes.map((n, i) => {
      const prior = old.get(n.id);
      return {
        ...n,
        x: prior ? prior.x : Math.cos(i) * 140 + (Math.random() - 0.5) * 60,
        y: prior ? prior.y : Math.sin(i) * 140 + (Math.random() - 0.5) * 60,
        vx: prior ? prior.vx : 0,
        vy: prior ? prior.vy : 0,
        hidden: false,
        dim: false,
      };
    });
    edges = (g.edges || []).map((e) => ({ ...e, source: String(e.source), target: String(e.target) }));
    byId = new Map(nodes.map((n) => [n.id, n]));
    edges = edges.filter((e) => byId.has(e.source) && byId.has(e.target));

    alpha = 1;

    const statsEl = document.getElementById("stats");
    if (statsEl) statsEl.textContent = `${nodes.length} nodes · ${edges.length} edges`;

    renderLegend();
    populateFilters();
    populatePathOptions();

    if (!nodes.length) {
      setGraphStatus("empty", "No graph data yet", "Ingest a Graph JSON file from the Ingestion page.");
    } else {
      setGraphStatus(null);
    }

    if (prefs.preserveSelection) {
      if (prevSelectedId && byId.has(prevSelectedId)) selectNode(byId.get(prevSelectedId));
      if (prevEdge) {
        const e = edges.find((x) => x.source === prevEdge.source && x.target === prevEdge.target && x.kind === prevEdge.kind);
        if (e) selectEdge(e);
      }
    }
  } catch (e) {
    setGraphStatus("error", "Failed to load graph", e.message);
    const statsEl = document.getElementById("stats");
    if (statsEl) statsEl.textContent = "Failed to load graph";
  }
}

function renderLegend() {
  const legendEl = document.getElementById("legend");
  if (!legendEl) return;
  const kinds = [...new Set(nodes.map((n) => n.kind))].sort();
  const cats = [...new Set(edges.map((e) => edgeCategory(e.kind)))].sort();
  let html = `<span class="legend-group">Nodes</span>`;
  html += kinds.map((k) => `<span><i style="background:${COLORS[k] || "#888"}"></i>${esc(k)}</span>`).join("");
  if (cats.length) {
    html += `<span class="legend-group">Edges</span>`;
    html += cats.map((c) => {
      const info = EDGE_CATEGORIES[c] || { label: "Other", color: EDGE_COLOR_DEFAULT };
      return `<span class="edge-legend"><i style="background:${info.color}"></i>${esc(info.label)}</span>`;
    }).join("");
  }
  legendEl.innerHTML = html;
  legendEl.classList.toggle("visible", !!prefs.legend && nodes.length > 0);
}

function populateFilters() {
  const nodeKindFilter = document.getElementById("nodeKindFilter");
  const edgeKindFilter = document.getElementById("edgeKindFilter");
  if (nodeKindFilter) {
    const cur = nodeKindFilter.value;
    const kinds = [...new Set(nodes.map((n) => n.kind))].sort();
    nodeKindFilter.innerHTML = '<option value="">All Types</option>' + kinds.map((k) => `<option value="${esc(k)}">${esc(k)}</option>`).join("");
    if (kinds.indexOf(cur) !== -1) nodeKindFilter.value = cur;
  }
  if (edgeKindFilter) {
    const cur = edgeKindFilter.value;
    const kinds = [...new Set(edges.map((e) => e.kind))].sort();
    edgeKindFilter.innerHTML = '<option value="">All Relationships</option>' + kinds.map((k) => `<option value="${esc(k)}">${esc(k)}</option>`).join("");
    if (kinds.indexOf(cur) !== -1) edgeKindFilter.value = cur;
  }
}

function step() {
  const vis = nodes.filter((n) => !nodeHidden(n));
  const n = vis.length;
  // Repulsion is O(n^2); skip it for very large graphs so the UI stays responsive.
  if (n <= 400) {
    for (let i = 0; i < n; i++) {
      for (let j = i + 1; j < n; j++) {
        const a = vis[i], b = vis[j];
        const dx = a.x - b.x, dy = a.y - b.y;
        const d2 = dx * dx + dy * dy || 0.01;
        const d = Math.sqrt(d2);
        const f = 1800 / d2;
        const fx = (dx / d) * f, fy = (dy / d) * f;
        a.vx += fx; a.vy += fy; b.vx -= fx; b.vy -= fy;
      }
    }
  }
  for (const e of edges) {
    if (edgeHidden(e)) continue;
    const a = byId.get(e.source), b = byId.get(e.target);
    if (!a || !b) continue;
    const dx = b.x - a.x, dy = b.y - a.y;
    const d = Math.sqrt(dx * dx + dy * dy) || 0.01;
    const f = (d - 110) * 0.02;
    const fx = (dx / d) * f, fy = (dy / d) * f;
    a.vx += fx; a.vy += fy; b.vx -= fx; b.vy -= fy;
  }
  for (const node of vis) {
    node.vx += -node.x * 0.002;
    node.vy += -node.y * 0.002;
    node.x += node.vx * alpha;
    node.y += node.vy * alpha;
    node.vx *= 0.85;
    node.vy *= 0.85;
  }
  alpha *= 0.99;
}

function draw() {
  if (!canvas || !ctx || !canvas.parentElement) return;
  const w = canvas.clientWidth, h = canvas.clientHeight;
  if (w === 0 || h === 0) return;
  ctx.clearRect(0, 0, w, h);

  // edges
  ctx.lineWidth = 1.2;
  for (const e of edges) {
    if (edgeHidden(e)) continue;
    const a = toScreen(byId.get(e.source));
    const b = toScreen(byId.get(e.target));
    const sel = selectedEdge && selectedEdge.source === e.source && selectedEdge.target === e.target && selectedEdge.kind === e.kind;
    ctx.strokeStyle = sel ? "#00ff88" : edgeColor(e.kind);
    ctx.globalAlpha = sel ? 1 : 0.5;
    ctx.beginPath();
    ctx.moveTo(a.x, a.y);
    ctx.lineTo(b.x, b.y);
    ctx.stroke();
  }
  ctx.globalAlpha = 1;

  // edge labels (explicit toggle; auto-show when zoomed in)
  if (prefs.edgeLabels || view.k > 1.2) {
    ctx.save();
    ctx.font = "10px ui-sans-serif,system-ui,sans-serif";
    ctx.fillStyle = "rgba(230,233,240,0.8)";
    ctx.textAlign = "center";
    ctx.textBaseline = "middle";
    for (const e of edges) {
      if (edgeHidden(e)) continue;
      const a = toScreen(byId.get(e.source));
      const b = toScreen(byId.get(e.target));
      ctx.fillText(e.kind, (a.x + b.x) / 2, (a.y + b.y) / 2);
    }
    ctx.restore();
  }

  // nodes
  for (const node of nodes) {
    if (nodeHidden(node)) continue;
    const p = toScreen(node);
    const r = (node.kind === "Domain" ? 12 : 8) * Math.max(0.6, Math.min(1.6, view.k));
    ctx.globalAlpha = node.dim ? 0.15 : 1;
    ctx.beginPath();
    ctx.arc(p.x, p.y, r, 0, Math.PI * 2);
    ctx.fillStyle = COLORS[node.kind] || "#888";
    ctx.fill();
    if (selectedNode === node) {
      ctx.lineWidth = 2.5;
      ctx.strokeStyle = "#fff";
      ctx.stroke();
    }
    if (prefs.labels && view.k > 0.7 && !node.dim) {
      ctx.fillStyle = "rgba(230,233,240,0.85)";
      ctx.font = "11px ui-sans-serif,system-ui,sans-serif";
      ctx.fillText(nodeLabel(node), p.x + r + 3, p.y + 3);
    }
    ctx.globalAlpha = 1;
  }
}

function loop() {
  if (alpha > 0.001 && prefs.physics) {
    for (let i = 0; i < 3; i++) step();
  }
  draw();
  requestAnimationFrame(loop);
}

// Run initial layout off-screen (fast-forward physics) before first render.
function settleLayout() {
  for (let i = 0; i < 200; i++) {
    step();
    if (alpha <= 0.01) break;
  }
  alpha = 0.1;
}

// ---- interaction ----

function hitNode(sx, sy) {
  const scaledRadius = 14 / Math.max(0.5, view.k);
  let best = null, bestD = scaledRadius;
  for (const n of nodes) {
    if (nodeHidden(n)) continue;
    const p = toScreen(n);
    const d = Math.hypot(p.x - sx, p.y - sy);
    if (d < bestD) { bestD = d; best = n; }
  }
  return best;
}

function distToSeg(px, py, ax, ay, bx, by) {
  const dx = bx - ax, dy = by - ay;
  const l2 = dx * dx + dy * dy || 0.01;
  let t = ((px - ax) * dx + (py - ay) * dy) / l2;
  t = Math.max(0, Math.min(1, t));
  return Math.hypot(px - (ax + t * dx), py - (ay + t * dy));
}

function hitEdge(sx, sy) {
  const scaledDist = 6 / Math.max(0.5, view.k);
  let best = null, bestD = scaledDist;
  for (const e of edges) {
    if (edgeHidden(e)) continue;
    const a = toScreen(byId.get(e.source));
    const b = toScreen(byId.get(e.target));
    const d = distToSeg(sx, sy, a.x, a.y, b.x, b.y);
    if (d < bestD) { bestD = d; best = e; }
  }
  return best;
}

function getCanvasCoords(ev) {
  const rect = canvas.getBoundingClientRect();
  return { x: ev.clientX - rect.left, y: ev.clientY - rect.top };
}

if (canvas) {
  canvas.addEventListener("mousedown", (ev) => {
    const c = getCanvasCoords(ev);
    const n = hitNode(c.x, c.y);
    drag.moved = false;
    drag.sx = c.x; drag.sy = c.y; drag.ox = view.x; drag.oy = view.y;
    if (n) { drag.node = n; n.fixed = true; }
    else { drag.panning = true; canvas.classList.add("dragging"); }
  });

  canvas.addEventListener("mousemove", (ev) => {
    const c = getCanvasCoords(ev);
    if (drag.node) {
      const w = toWorld(c.x, c.y);
      drag.node.x = w.x; drag.node.y = w.y;
      drag.node.vx = 0; drag.node.vy = 0;
      drag.moved = true;
      alpha = Math.max(alpha, 0.15);
    } else if (drag.panning) {
      view.x = drag.ox + (c.x - drag.sx);
      view.y = drag.oy + (c.y - drag.sy);
      drag.moved = true;
    }
  });

  canvas.addEventListener("mouseup", (ev) => {
    const c = getCanvasCoords(ev);
    canvas.classList.remove("dragging");
    if (drag.node) {
      drag.node.fixed = false;
      if (!drag.moved) selectNode(drag.node);
      drag.node = null;
    } else if (drag.panning) {
      if (!drag.moved) {
        const n = hitNode(c.x, c.y);
        if (n) selectNode(n);
        else {
          const e = hitEdge(c.x, c.y);
          if (e) selectEdge(e);
          else clearSelection();
        }
      }
      drag.panning = false;
    }
  });

  canvas.addEventListener("wheel", (ev) => {
    ev.preventDefault();
    const c = getCanvasCoords(ev);
    const before = toWorld(c.x, c.y);
    const factor = ev.deltaY < 0 ? 1.12 : 1 / 1.12;
    view.k = Math.max(0.15, Math.min(4, view.k * factor));
    const after = toWorld(c.x, c.y);
    view.x += (after.x - before.x) * view.k;
    view.y += (after.y - before.y) * view.k;
  }, { passive: false });

  canvas.addEventListener("touchstart", (ev) => {
    if (ev.touches.length === 1) {
      const c = getCanvasCoords(ev.touches[0]);
      const n = hitNode(c.x, c.y);
      drag.moved = false;
      drag.sx = c.x; drag.sy = c.y; drag.ox = view.x; drag.oy = view.y;
      if (n) { drag.node = n; n.fixed = true; }
      else { drag.panning = true; canvas.classList.add("dragging"); }
      ev.preventDefault();
    }
  }, { passive: false });

  canvas.addEventListener("touchmove", (ev) => {
    if (ev.touches.length === 1) {
      const c = getCanvasCoords(ev.touches[0]);
      if (drag.node) {
        const w = toWorld(c.x, c.y);
        drag.node.x = w.x; drag.node.y = w.y;
        drag.node.vx = 0; drag.node.vy = 0;
        drag.moved = true;
        alpha = Math.max(alpha, 0.15);
      } else if (drag.panning) {
        view.x = drag.ox + (c.x - drag.sx);
        view.y = drag.oy + (c.y - drag.sy);
        drag.moved = true;
      }
      ev.preventDefault();
    }
  }, { passive: false });

  canvas.addEventListener("touchend", (ev) => {
    let sx = drag.sx, sy = drag.sy;
    if (ev.changedTouches.length === 1) {
      const c = getCanvasCoords(ev.changedTouches[0]);
      sx = c.x; sy = c.y;
    }
    canvas.classList.remove("dragging");
    if (drag.node) {
      drag.node.fixed = false;
      if (!drag.moved) selectNode(drag.node);
      drag.node = null;
    } else if (drag.panning) {
      if (!drag.moved) {
        const n = hitNode(sx, sy);
        if (n) selectNode(n);
        else {
          const e = hitEdge(sx, sy);
          if (e) selectEdge(e);
        }
      }
      drag.panning = false;
    }
  });
}

function fitView() {
  const vis = visibleNodes();
  if (vis.length === 0) return;
  let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
  for (const n of vis) {
    minX = Math.min(minX, n.x); minY = Math.min(minY, n.y);
    maxX = Math.max(maxX, n.x); maxY = Math.max(maxY, n.y);
  }
  if (!isFinite(minX)) return;
  const w = canvas.clientWidth, h = canvas.clientHeight;
  const cx = (minX + maxX) / 2, cy = (minY + maxY) / 2;
  const scaleX = w / Math.max(1, maxX - minX + 100);
  const scaleY = h / Math.max(1, maxY - minY + 100);
  view.k = Math.min(scaleX, scaleY, 3);
  view.x = w / 2 - cx * view.k;
  view.y = h / 2 - cy * view.k;
}

function resetView() {
  view = { x: 0, y: 0, k: 1 };
  fitView();
}

function centerSelection() {
  if (selectedNode) {
    const w = canvas.clientWidth, h = canvas.clientHeight;
    const p = toScreen(selectedNode);
    view.x = w / 2 - p.x;
    view.y = h / 2 - p.y;
  } else if (selectedEdge) {
    const a = toScreen(byId.get(selectedEdge.source));
    const b = toScreen(byId.get(selectedEdge.target));
    const w = canvas.clientWidth, h = canvas.clientHeight;
    view.x = w / 2 - (a.x + b.x) / 2;
    view.y = h / 2 - (a.y + b.y) / 2;
  }
}

// Apply the toolbar node-kind / relationship filters and the search dimming.
function applyFilters() {
  const nodeKind = val("nodeKindFilter");
  const searchQ = val("search").toLowerCase();
  for (const n of nodes) {
    n.hidden = !!(nodeKind && n.kind !== nodeKind);
    const hay = `${n.name || ""} ${n.sam_account_name || ""} ${n.id}`.toLowerCase();
    n.dim = searchQ !== "" && !hay.includes(searchQ);
  }
  const centerBtn = document.getElementById("centerSelection");
  if (centerBtn) centerBtn.disabled = !(selectedNode || selectedEdge);
  draw();
}

// ---------------------------------------------------------------------------
// Panels & inspector
// ---------------------------------------------------------------------------

function show(id) {
  for (const s of ["panel-empty", "panel-node", "panel-edge"]) {
    const el = document.getElementById(s);
    if (el) el.hidden = s !== id;
  }
}

function clearSelection() {
  selectedNode = null;
  selectedEdge = null;
  show("panel-empty");
  const centerBtn = document.getElementById("centerSelection");
  if (centerBtn) centerBtn.disabled = true;
}

function selectNode(n) {
  if (!n) return;
  selectedNode = n;
  selectedEdge = null;
  show("panel-node");
  const titleEl = document.getElementById("node-title");
  if (titleEl) {
    titleEl.innerHTML = `${esc(nodeLabel(n))} <span class="node-kind-badge" style="background:${COLORS[n.kind] || "#888"};color:#0b0e14">${esc(n.kind)}</span>`;
  }
  const rows = [
    ["kind", n.kind],
    ["sid", n.id],
    ["sam", n.sam_account_name || ""],
    ["domain", n.domain || ""],
    ["dn", n.distinguished_name || ""],
    ...Object.entries(n.props || {}),
  ].filter(([, v]) => v !== "" && v !== undefined && v !== null);
  const propsEl = document.getElementById("node-props");
  if (propsEl) {
    propsEl.innerHTML = rows.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(String(v))}</dd>`).join("");
  }

  const out = edges.filter((e) => e.source === n.id);
  const inc = edges.filter((e) => e.target === n.id);
  const outEl = document.getElementById("node-out");
  const inEl = document.getElementById("node-in");
  if (outEl) outEl.innerHTML = edgeList(out, "target");
  if (inEl) inEl.innerHTML = edgeList(inc, "source");
  const outCount = document.getElementById("nodeOutCount");
  const inCount = document.getElementById("nodeInCount");
  if (outCount) outCount.textContent = out.length;
  if (inCount) inCount.textContent = inc.length;

  for (const li of document.querySelectorAll("#node-out li,#node-in li")) {
    li.addEventListener("click", () => {
      const e = edges.find((x) => x.source === li.dataset.src && x.target === li.dataset.tgt && x.kind === li.dataset.kind);
      if (e) selectEdge(e);
    });
  }

  const openBtn = document.getElementById("openInGraph");
  if (openBtn) {
    openBtn.disabled = false;
    openBtn.textContent = "Center in Graph";
    openBtn.dataset.nodeId = n.id;
  }
  const centerBtn = document.getElementById("centerSelection");
  if (centerBtn) centerBtn.disabled = false;
  draw();
}

function edgeList(list, other) {
  if (!list.length) return "<li class='muted'>none</li>";
  return list.map((e) => {
    const o = byId.get(e[other]);
    const name = o ? nodeLabel(o) : e[other];
    return `<li data-src="${esc(e.source)}" data-tgt="${esc(e.target)}" data-kind="${esc(e.kind)}"><span class="k">${esc(e.kind)}</span> <span class="target">→ ${esc(name)}</span></li>`;
  }).join("");
}

async function selectEdge(e) {
  if (!e) return;
  selectedEdge = e;
  selectedNode = null;
  show("panel-edge");
  const a = byId.get(e.source), b = byId.get(e.target);
  const titleEl = document.getElementById("edge-title");
  const summaryEl = document.getElementById("edge-summary");
  if (titleEl) titleEl.innerHTML = `${esc(e.kind)} <span class="node-kind-badge" style="background:${edgeColor(e.kind)};color:#0b0e14">${esc((EDGE_CATEGORIES[edgeCategory(e.kind)] || {}).label || "Other")}</span>`;
  if (summaryEl) summaryEl.textContent = `${a ? nodeLabel(a) : e.source} → ${b ? nodeLabel(b) : e.target}`;

  const cmdEl = document.getElementById("edge-command");
  const opsecEl = document.getElementById("edge-opsec");
  const eventsEl = document.getElementById("edge-events");
  const warningsEl = document.getElementById("edge-warnings");
  const altsWrap = document.getElementById("edge-alts-wrap");
  const altsEl = document.getElementById("edge-alts");
  const propsEl = document.getElementById("edge-props");
  if (cmdEl) cmdEl.textContent = "loading…";
  if (opsecEl) opsecEl.textContent = "";
  if (eventsEl) eventsEl.textContent = "";
  if (warningsEl) warningsEl.textContent = "";
  if (altsWrap) altsWrap.hidden = true;
  if (propsEl) propsEl.innerHTML = Object.entries(e.props || {}).map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(String(v))}</dd>`).join("");

  const centerBtn = document.getElementById("centerSelection");
  if (centerBtn) centerBtn.disabled = false;
  draw();

  try {
    const r = await apiGet(`/api/v1/abuse?src=${encodeURIComponent(e.source)}&kind=${encodeURIComponent(e.kind)}&dst=${encodeURIComponent(e.target)}`);
    if (cmdEl) cmdEl.textContent = r.command || "";
    if (opsecEl) opsecEl.textContent = r.opsec || "";
    if (eventsEl) eventsEl.textContent = (r.event_ids && r.event_ids.length) ? "Event IDs: " + r.event_ids.join(", ") : "";
    if (warningsEl) warningsEl.textContent = (r.warnings && r.warnings.length) ? "⚠ " + r.warnings.join("; ") : "";
    if (r.alternates && r.alternates.length && altsWrap && altsEl) {
      altsWrap.hidden = false;
      altsEl.textContent = r.alternates.join("\n");
    }
  } catch (err) {
    if (cmdEl) cmdEl.textContent = "No abuse template available: " + err.message;
  }
}

// ---------------------------------------------------------------------------
// Routing (hash based: back/forward/refresh friendly)
// ---------------------------------------------------------------------------

function parseHash() {
  const h = (location.hash || "").replace(/^#\/?/, "").trim();
  return VIEWS.indexOf(h) !== -1 ? h : "graph";
}

function setView(name, push = true) {
  if (VIEWS.indexOf(name) === -1) name = "graph";
  if (push) {
    if (parseHash() === name) {
      renderView(name);
    } else {
      location.hash = "#/" + name; // triggers hashchange -> renderView
    }
  } else {
    renderView(name);
  }
}

function renderView(name) {
  document.querySelectorAll(".view").forEach((v) => v.classList.toggle("active", v.id === "view-" + name));
  document.querySelectorAll(".nav-btn").forEach((b) => b.classList.toggle("active", b.dataset.view === name));
  document.title = "OmenHound · " + name.charAt(0).toUpperCase() + name.slice(1);

  // Close the mobile sidebar after navigation.
  const sidebarEl = document.getElementById("sidebar");
  const overlay = document.querySelector(".sidebar-overlay");
  if (sidebarEl) sidebarEl.classList.remove("open");
  if (overlay) overlay.classList.remove("visible");

  if (name === "graph") {
    setTimeout(() => { resize(); fitView(); }, 10);
  } else if (name === "overview") {
    loadOverview();
  } else if (name === "domains") {
    loadDomains();
  } else if (["users", "groups", "computers", "ous", "gpos", "containers"].indexOf(name) !== -1) {
    loadTable(name, 0);
  } else if (name === "trusts") {
    loadTrusts();
  } else if (name === "relationships") {
    loadRelationships(0);
  } else if (name === "paths") {
    populatePathOptions();
    populatePathSuggestFromGraph();
  } else if (name === "audit") {
    loadAudit();
  } else if (name === "settings") {
    loadAbout();
  } else if (name === "ingestion") {
    populateIngestionCommands();
  }
}

function attachNav() {
  document.querySelectorAll(".nav-btn").forEach((b) => {
    b.removeEventListener("click", navClick);
    b.addEventListener("click", navClick);
  });
}

function navClick() {
  const v = this.dataset.view;
  if (v) setView(v);
}

window.addEventListener("hashchange", () => { renderView(parseHash()); });

// ---------------------------------------------------------------------------
// Overview
// ---------------------------------------------------------------------------

async function loadOverview() {
  const grid = document.getElementById("overviewGrid");
  if (grid) grid.innerHTML = stateHTML("loading", "Loading statistics…");
  try {
    const [stats, health] = await Promise.all([apiGet("/api/v1/stats"), apiGet("/api/v1/health").catch(() => null)]);
    statsCache = stats;
    const kinds = stats.kinds || {};
    const cards = [
      { label: "Nodes", value: stats.nodes, cls: "edge" },
      { label: "Edges", value: stats.edges, cls: "edge" },
      { label: "Users", value: kinds.User || 0, cls: "user" },
      { label: "Groups", value: kinds.Group || 0, cls: "group" },
      { label: "Computers", value: kinds.Computer || 0, cls: "computer" },
      { label: "Domains", value: kinds.Domain || 0, cls: "domain" },
      { label: "OUs", value: kinds.OU || 0, cls: "ou" },
      { label: "GPOs", value: kinds.GPO || 0, cls: "gpo" },
      { label: "Containers", value: kinds.Container || 0, cls: "container" },
      { label: "Trusts", value: kinds.Trust || 0, cls: "trust" },
    ];
    if (grid) {
      grid.innerHTML = cards.map((s) =>
        `<div class="stat-card ${s.cls}"><div class="icon">${s.cls === "edge" ? "⛶" : s.label[0]}</div><div class="value">${s.value}</div><div class="label">${esc(s.label)}</div></div>`
      ).join("");
    }
    if (health) {
      const healthEl = document.getElementById("health");
      if (healthEl) {
        healthEl.textContent = `v${health.version} · credential-ops ${health.credential_ops_enabled ? "ON" : "off"} · write-api ${health.write_api_enabled ? "ON" : "off"}`;
        healthEl.className = "stats " + (health.write_api_enabled ? "success" : "muted");
      }
    }
    loadRecentActivity();
  } catch (e) {
    if (grid) grid.innerHTML = stateHTML("error", "Failed to load statistics", e.message);
  }
}

async function loadRecentActivity() {
  const card = document.getElementById("recentActivityCard");
  const list = document.getElementById("recentActivity");
  if (!card || !list) return;
  try {
    const j = await apiGet("/api/v1/audit?limit=8");
    const events = j.events || [];
    if (!events.length) { card.hidden = true; return; }
    card.hidden = false;
    list.innerHTML = events.map((e) => {
      const cls = e.result === "ok" ? "ingest" : "warn";
      const when = e.time ? new Date(e.time).toLocaleString() : "";
      return `<div class="activity-item"><div class="activity-icon ${cls}">${e.result === "ok" ? "✓" : "⚠"}</div>
        <div class="activity-content"><div class="activity-title">${esc(e.action || "")}${e.target ? " → " + esc(e.target) : ""}</div>
        <div class="activity-meta">${esc(e.actor || "")} · ${esc(e.result || "")}${e.reason ? " · " + esc(e.reason) : ""} · ${esc(when)}</div></div></div>`;
    }).join("");
  } catch (_) {
    card.hidden = true;
  }
}

// ---------------------------------------------------------------------------
// Object / relationship detail modal
// ---------------------------------------------------------------------------

let modalCtx = null;

function openModal() {
  const m = document.getElementById("objectModal");
  if (m) m.hidden = false;
}
function closeObjectModal() {
  const m = document.getElementById("objectModal");
  if (m) m.hidden = true;
  modalCtx = null;
}

async function openObject(id) {
  modalCtx = { type: "node", id };
  const title = document.getElementById("objTitle");
  const body = document.getElementById("objBody");
  if (title) title.textContent = "Object";
  if (body) body.innerHTML = stateHTML("loading", "Loading object…");
  openModal();
  toggleModalButtons({ graph: false, path: false });
  try {
    const [n, rel] = await Promise.all([
      apiGet(`/api/v1/objects/${encodeURIComponent(id)}`),
      apiGet(`/api/v1/objects/${encodeURIComponent(id)}/relationships`).catch(() => ({ outgoing: [], incoming: [] })),
    ]);
    if (title) title.innerHTML = `${esc(nodeLabel(n))} <span class="obj-kind-badge" style="background:${COLORS[n.kind] || "#888"}">${esc(n.kind)}</span>`;
    const rows = [
      ["kind", n.kind], ["sid", n.id], ["sam", n.sam_account_name], ["domain", n.domain],
      ["distinguished_name", n.distinguished_name], ...Object.entries(n.props || {}),
    ].filter(([, v]) => v !== "" && v !== undefined && v !== null);
    const outgoing = rel.outgoing || [];
    const incoming = rel.incoming || [];
    if (body) {
      body.innerHTML = `
        <h3>Properties</h3>
        <dl class="obj-props">${rows.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(String(v))}</dd>`).join("") || "<dt>—</dt><dd>no properties collected</dd>"}</dl>
        <h3>Outgoing relationships (${outgoing.length})</h3>
        <ul class="obj-rel-list">${objectRelList(outgoing, "target")}</ul>
        <h3>Incoming relationships (${incoming.length})</h3>
        <ul class="obj-rel-list">${objectRelList(incoming, "source")}</ul>`;
      body.querySelectorAll(".obj-rel-list li[data-id]").forEach((li) => {
        li.addEventListener("click", () => openObject(li.dataset.id));
      });
    }
    toggleModalButtons({ graph: true, path: true });
  } catch (e) {
    if (body) body.innerHTML = stateHTML("error", "Failed to load object", e.message);
  }
}

function objectRelList(list, other) {
  if (!list.length) return "<li class='muted' style='cursor:default'>none</li>";
  return list.map((e) => {
    const oid = e[other];
    const o = byId.get(oid);
    const name = o ? nodeLabel(o) : oid;
    return `<li data-id="${esc(oid)}"><span class="k">${esc(e.kind)}</span> ${other === "target" ? "→" : "←"} ${esc(name)}</li>`;
  }).join("");
}

function toggleModalButtons({ graph, path }) {
  const g = document.getElementById("objOpenGraph");
  const p = document.getElementById("objFindPath");
  if (g) g.hidden = !graph;
  if (p) p.hidden = !path;
}

function openEdgeModal(e) {
  modalCtx = { type: "edge", edge: e };
  const title = document.getElementById("objTitle");
  const body = document.getElementById("objBody");
  const a = byId.get(e.source), b = byId.get(e.target);
  if (title) title.innerHTML = `${esc(e.kind)} <span class="obj-kind-badge" style="background:${edgeColor(e.kind)}">Relationship</span>`;
  if (body) {
    body.innerHTML = `
      <h3>Relationship</h3>
      <dl class="obj-props">
        <dt>type</dt><dd>${esc(e.kind)}</dd>
        <dt>source</dt><dd>${esc(a ? nodeLabel(a) : e.source)}</dd>
        <dt>target</dt><dd>${esc(b ? nodeLabel(b) : e.target)}</dd>
        <dt>source_sid</dt><dd>${esc(e.source)}</dd>
        <dt>target_sid</dt><dd>${esc(e.target)}</dd>
        ${Object.entries(e.props || {}).map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(String(v))}</dd>`).join("")}
      </dl>
      <h3>Dynamic Abuse Command</h3>
      <div class="command-block"><pre id="modal-edge-command">loading…</pre></div>`;
  }
  toggleModalButtons({ graph: true, path: true });
  openModal();
  apiGet(`/api/v1/abuse?src=${encodeURIComponent(e.source)}&kind=${encodeURIComponent(e.kind)}&dst=${encodeURIComponent(e.target)}`)
    .then((r) => { const el = document.getElementById("modal-edge-command"); if (el) el.textContent = r.command || "(no template)"; })
    .catch((err) => { const el = document.getElementById("modal-edge-command"); if (el) el.textContent = "No abuse template available: " + err.message; });
}

// "Open in Graph" / "Find Paths" from the modal.
function modalOpenInGraph() {
  if (!modalCtx) return;
  const ctx = modalCtx;
  closeObjectModal();
  setView("graph");
  if (ctx.type === "node") {
    const n = byId.get(ctx.id);
    if (n) { selectNode(n); setTimeout(() => { centerSelection(); draw(); }, 60); }
  } else if (ctx.type === "edge") {
    const e = ctx.edge;
    selectEdge(e);
    setTimeout(() => { centerSelection(); draw(); }, 60);
  }
}

function modalFindPaths() {
  if (!modalCtx) return;
  const ctxSnapshot = modalCtx;
  closeObjectModal();
  setView("paths");
  if (ctxSnapshot.type === "node") {
    pathSrcSel = ctxSnapshot.id;
    const el = document.getElementById("pathSrc");
    const n = byId.get(ctxSnapshot.id);
    if (el) el.value = n ? nodeLabel(n) : ctxSnapshot.id;
  } else if (ctxSnapshot.type === "edge") {
    pathSrcSel = ctxSnapshot.edge.source;
    pathDstSel = ctxSnapshot.edge.target;
    const sn = byId.get(ctxSnapshot.edge.source);
    const dn = byId.get(ctxSnapshot.edge.target);
    const se = document.getElementById("pathSrc"), de = document.getElementById("pathDst");
    if (se) se.value = sn ? nodeLabel(sn) : ctxSnapshot.edge.source;
    if (de) de.value = dn ? nodeLabel(dn) : ctxSnapshot.edge.target;
  }
}

// ---------------------------------------------------------------------------
// Generic list tables (server-side search/sort/filter/pagination)
// ---------------------------------------------------------------------------

const TABLE_DEFS = {
  users: {
    type: "User", body: "usersBody", pager: "usersPage", search: "userSearch", sort: "userSort", table: "usersTable",
    attrs: () => { const v = val("userEnabledFilter"); return v ? { enabled: v } : {}; },
    row: (n) => `<tr class="clickable" data-id="${esc(n.id)}">
      <td><strong>${esc(n.name || "—")}</strong></td>
      <td>${esc(n.sam_account_name || "—")}</td>
      <td>${esc(n.domain || "—")}</td>
      <td class="${flag(n, "enabled") ? "enabled" : "disabled"}">${flag(n, "enabled") ? "Yes" : "No"}</td>
      <td><span class="mono">${esc(n.id)}</span></td></tr>`,
  },
  groups: {
    type: "Group", body: "groupsBody", pager: "groupsPage", search: "groupSearch", sort: "groupSort", table: "groupsTable",
    attrs: () => { const v = val("groupTypeFilter"); return v ? { type: v } : {}; },
    row: (n) => `<tr class="clickable" data-id="${esc(n.id)}">
      <td><strong>${esc(n.name || "—")}</strong></td>
      <td>${esc((n.props && n.props.type) || "—")}</td>
      <td>${esc(n.domain || "—")}</td>
      <td>${esc((n.props && n.props.member_count) || "—")}</td>
      <td><span class="mono">${esc(n.id)}</span></td></tr>`,
  },
  computers: {
    type: "Computer", body: "compsBody", pager: "compsPage", search: "compSearch", sort: "compSort", table: "compsTable",
    attrs: () => { const v = val("compOsFilter"); return v ? { os: v } : {}; },
    row: (n) => `<tr class="clickable" data-id="${esc(n.id)}">
      <td><strong>${esc(n.name || "—")}</strong></td>
      <td>${esc(n.domain || "—")}</td>
      <td>${esc((n.props && n.props.os) || "—")}</td>
      <td><span class="mono">${esc(n.id)}</span></td></tr>`,
  },
  ous: {
    type: "OU", body: "ousBody", pager: "ousPage", search: "ouSearch", sort: "ouSort", table: "ousTable",
    row: (n) => `<tr class="clickable" data-id="${esc(n.id)}">
      <td><strong>${esc(n.name || "—")}</strong></td>
      <td>${esc(n.domain || "—")}</td>
      <td><span class="mono">${esc(n.distinguished_name || "—")}</span></td>
      <td><span class="mono">${esc(n.id)}</span></td></tr>`,
  },
  gpos: {
    type: "GPO", body: "gposBody", pager: "gposPage", search: "gpoSearch", sort: "gpoSort", table: "gposTable",
    row: (n) => `<tr class="clickable" data-id="${esc(n.id)}">
      <td><strong>${esc(n.name || "—")}</strong></td>
      <td>${esc(n.domain || "—")}</td>
      <td><span class="mono">${esc((n.props && n.props.guid) || "—")}</span></td>
      <td><span class="mono">${esc(n.id)}</span></td></tr>`,
  },
  containers: {
    type: "Container", body: "containersBody", pager: "containersPage", search: "containerSearch", sort: "containerSort", table: "containersTable",
    row: (n) => `<tr class="clickable" data-id="${esc(n.id)}">
      <td><strong>${esc(n.name || "—")}</strong></td>
      <td>${esc(n.domain || "—")}</td>
      <td><span class="mono">${esc(n.distinguished_name || "—")}</span></td>
      <td><span class="mono">${esc(n.id)}</span></td></tr>`,
  },
};

function tableStateRow(def, bodyEl, kind, detail) {
  const cols = document.querySelectorAll(`#${def.table} thead th`).length || 4;
  bodyEl.innerHTML = `<tr class="state-row"><td colspan="${cols}">${stateHTML(kind, kind === "empty" ? "No matching records" : "", detail)}</td></tr>`;
}

async function loadTable(name, offset) {
  const def = TABLE_DEFS[name];
  if (!def) return;
  const st = tableState[name] || (tableState[name] = { limit: 50, offset: 0, total: 0 });
  st.offset = offset || 0;
  const bodyEl = document.getElementById(def.body);
  if (!bodyEl) return;
  tableStateRow(def, bodyEl, "loading", "Loading…");

  const params = new URLSearchParams();
  params.set("type", def.type);
  params.set("limit", String(st.limit));
  params.set("offset", String(st.offset));
  const q = val(def.search); if (q) params.set("search", q);
  const s = val(def.sort); if (s) params.set("sort", s);
  if (currentDomain) params.set("domain", currentDomain);
  const attrs = def.attrs ? def.attrs() : {};
  for (const k of Object.keys(attrs)) if (attrs[k]) params.set("attr_" + k, attrs[k]);

  try {
    const j = await apiGet("/api/v1/objects?" + params.toString());
    const items = j.nodes || [];
    st.total = j.total || 0;
    if (!items.length) {
      tableStateRow(def, bodyEl, "empty");
    } else {
      bodyEl.innerHTML = items.map(def.row).join("");
    }
    renderPager(document.getElementById(def.pager), st.total, st.limit, st.offset, (off) => loadTable(name, off));
  } catch (e) {
    tableStateRow(def, bodyEl, "error", e.message);
    renderPager(document.getElementById(def.pager), 0, st.limit, 0, () => {});
  }
}

function renderPager(el, total, limit, offset, onGo) {
  if (!el) return;
  if (!total) { el.innerHTML = ""; return; }
  const pages = Math.max(1, Math.ceil(total / limit));
  const cur = Math.floor(offset / limit) + 1;
  let html = `<button class="page-btn" data-off="${Math.max(0, cur - 2) * limit}" ${cur === 1 ? "disabled" : ""} aria-label="Previous page">‹</button>`;
  const start = Math.max(1, cur - 2);
  const end = Math.min(pages, start + 4);
  for (let p = start; p <= end; p++) {
    html += `<button class="page-btn ${p === cur ? "active" : ""}" data-off="${(p - 1) * limit}">${p}</button>`;
  }
  html += `<button class="page-btn" data-off="${Math.min(pages - 1, cur) * limit}" ${cur === pages ? "disabled" : ""} aria-label="Next page">›</button>`;
  html += `<span class="page-info">${total} record${total === 1 ? "" : "s"} · page ${cur}/${pages}</span>`;
  el.innerHTML = html;
  el.querySelectorAll("button.page-btn").forEach((b) => {
    b.addEventListener("click", () => {
      if (b.disabled) return;
      const off = parseInt(b.dataset.off, 10);
      if (!isNaN(off)) onGo(off);
    });
  });
}

function wireTableControls() {
  Object.keys(TABLE_DEFS).forEach((name) => {
    const def = TABLE_DEFS[name];
    const searchEl = document.getElementById(def.search);
    if (searchEl) {
      let t = null;
      searchEl.addEventListener("input", () => {
        clearTimeout(t);
        t = setTimeout(() => loadTable(name, 0), 250);
      });
    }
    const sortEl = document.getElementById(def.sort);
    if (sortEl) sortEl.addEventListener("change", () => loadTable(name, 0));
    const bodyEl = document.getElementById(def.body);
    if (bodyEl) {
      bodyEl.addEventListener("click", (ev) => {
        const tr = ev.target.closest ? ev.target.closest("tr[data-id]") : null;
        if (tr) openObject(tr.dataset.id);
      });
    }
  });
  // Per-view filter selects.
  const userEnabled = document.getElementById("userEnabledFilter");
  if (userEnabled) userEnabled.addEventListener("change", () => loadTable("users", 0));
  const groupType = document.getElementById("groupTypeFilter");
  if (groupType) groupType.addEventListener("change", () => loadTable("groups", 0));
  const compOs = document.getElementById("compOsFilter");
  if (compOs) compOs.addEventListener("change", () => loadTable("computers", 0));
}

// Populate group-type and computer-OS filter options from data actually present.
function populateDynamicFilters() {
  const groupType = document.getElementById("groupTypeFilter");
  if (groupType) {
    const cur = groupType.value;
    const types = [...new Set(nodes.filter((n) => n.kind === "Group").map((n) => n.props && n.props.type).filter(Boolean))].sort();
    groupType.innerHTML = '<option value="">All Types</option>' + types.map((t) => `<option value="${esc(t)}">${esc(t)}</option>`).join("");
    if (types.indexOf(cur) !== -1) groupType.value = cur;
    groupType.title = types.length ? "" : "No group 'type' attribute present in the collected data";
  }
  const compOs = document.getElementById("compOsFilter");
  if (compOs) {
    const cur = compOs.value;
    const oses = [...new Set(nodes.filter((n) => n.kind === "Computer").map((n) => n.props && n.props.os).filter(Boolean))].sort();
    compOs.innerHTML = '<option value="">All OS</option>' + oses.map((o) => `<option value="${esc(o)}">${esc(o)}</option>`).join("");
    if (oses.indexOf(cur) !== -1) compOs.value = cur;
  }
}

// ---------------------------------------------------------------------------
// Domains
// ---------------------------------------------------------------------------

async function loadDomains() {
  const list = document.getElementById("domainsList");
  const searchEl = document.getElementById("domainSearch");
  if (!list) return;
  list.innerHTML = stateHTML("loading", "Loading domains…");
  try {
    const j = await apiGet("/api/v1/domains");
    const domains = j.domains || [];
    const counts = {};
    for (const n of nodes) {
      if (n.domain) counts[n.domain] = (counts[n.domain] || 0) + 1;
    }
    const q = searchEl ? searchEl.value.toLowerCase() : "";
    const filtered = domains.filter((d) => !q || d.toLowerCase().includes(q));
    if (!domains.length) {
      list.innerHTML = stateHTML("empty", "No domains in the graph", "Ingest data to populate domains.");
      return;
    }
    if (!filtered.length) {
      list.innerHTML = stateHTML("empty", "No domains match the filter");
      return;
    }
    list.innerHTML = filtered.map((d) =>
      `<div class="list-item clickable" data-domain="${esc(d)}" style="cursor:pointer;padding:10px;border:1px solid var(--line);border-radius:var(--rad-md);margin-bottom:6px;background:var(--panel2)">
        <strong>${esc(d)}</strong> <span class="muted small">${counts[d] || 0} objects in graph</span>
      </div>`).join("");
    list.querySelectorAll(".list-item[data-domain]").forEach((el) => {
      el.addEventListener("click", () => {
        const sel = document.getElementById("domainSelect");
        if (sel) sel.value = el.dataset.domain;
        currentDomain = el.dataset.domain;
        setView("users");
      });
    });
  } catch (e) {
    list.innerHTML = stateHTML("error", "Failed to load domains", e.message);
  }
}

// ---------------------------------------------------------------------------
// Trusts
// ---------------------------------------------------------------------------

let trustCache = [];

async function loadTrusts() {
  const bodyEl = document.getElementById("trustsBody");
  if (!bodyEl) return;
  bodyEl.innerHTML = `<tr class="state-row"><td colspan="5">${stateHTML("loading", "Loading trusts…")}</td></tr>`;
  try {
    const j = await apiGet("/api/v1/trusts");
    trustCache = j.trusts || [];
    renderTrusts();
    const searchEl = document.getElementById("trustSearch");
    if (searchEl && !searchEl.dataset.wired) {
      searchEl.dataset.wired = "1";
      searchEl.addEventListener("input", renderTrusts);
    }
    const sortEl = document.getElementById("trustSort");
    if (sortEl && !sortEl.dataset.wired) {
      sortEl.dataset.wired = "1";
      sortEl.addEventListener("change", renderTrusts);
    }
  } catch (e) {
    bodyEl.innerHTML = `<tr class="state-row"><td colspan="5">${stateHTML("error", "Failed to load trusts", e.message)}</td></tr>`;
  }
}

function renderTrusts() {
  const bodyEl = document.getElementById("trustsBody");
  if (!bodyEl) return;
  const q = val("trustSearch").toLowerCase();
  const sortKey = val("trustSort") || "source";
  let rows = trustCache.filter((t) => {
    if (!q) return true;
    return `${t.source || ""} ${t.target || ""} ${t.type || ""}`.toLowerCase().includes(q);
  });
  rows.sort((a, b) => String(a[sortKey] || "").localeCompare(String(b[sortKey] || "")));
  if (!rows.length) {
    bodyEl.innerHTML = `<tr class="state-row"><td colspan="5">${stateHTML("empty", trustCache.length ? "No trusts match the filter" : "No domain trusts recorded")}</td></tr>`;
    return;
  }
  bodyEl.innerHTML = rows.map((t) => `<tr>
    <td><strong>${esc(t.source || "—")}</strong></td>
    <td>${esc(t.target || "—")}</td>
    <td>${esc(t.type || "—")}</td>
    <td>${t.transitive ? "Yes" : "No"}</td>
    <td>${t.sid_filtering ? "Yes" : "No"}</td></tr>`).join("");
}

// ---------------------------------------------------------------------------
// Relationships (from the graph's real edge set, filtered + paginated client-side)
// ---------------------------------------------------------------------------

let relFiltered = [];
let relPage = 0;
const REL_PAGE_SIZE = 50;

async function loadRelationships() {
  const bodyEl = document.getElementById("relsBody");
  if (!bodyEl) return;
  if (!nodes.length) await loadGraph();
  renderRelationships();
  const searchEl = document.getElementById("relSearch");
  if (searchEl && !searchEl.dataset.wired) {
    searchEl.dataset.wired = "1";
    let t = null;
    searchEl.addEventListener("input", () => { clearTimeout(t); t = setTimeout(() => { relPage = 0; renderRelationships(); }, 200); });
  }
  const kindEl = document.getElementById("relKindFilter");
  if (kindEl) {
    const cur = kindEl.value;
    const kinds = [...new Set(edges.map((e) => e.kind))].sort();
    kindEl.innerHTML = '<option value="">All Types</option>' + kinds.map((k) => `<option value="${esc(k)}">${esc(k)}</option>`).join("");
    if (kinds.indexOf(cur) !== -1) kindEl.value = cur;
    if (!kindEl.dataset.wired) {
      kindEl.dataset.wired = "1";
      kindEl.addEventListener("change", () => { relPage = 0; renderRelationships(); });
    }
  }
  const sortEl = document.getElementById("relSort");
  if (sortEl && !sortEl.dataset.wired) {
    sortEl.dataset.wired = "1";
    sortEl.addEventListener("change", () => { relPage = 0; renderRelationships(); });
  }
}

function renderRelationships() {
  const bodyEl = document.getElementById("relsBody");
  if (!bodyEl) return;
  const q = val("relSearch").toLowerCase();
  const kind = val("relKindFilter");
  const sortKey = val("relSort") || "kind";
  const nameOf = (id) => { const n = byId.get(id); return n ? nodeLabel(n) : id; };

  relFiltered = edges.filter((e) => {
    if (kind && e.kind !== kind) return false;
    if (!q) return true;
    const hay = `${e.kind} ${e.source} ${e.target} ${nameOf(e.source)} ${nameOf(e.target)}`.toLowerCase();
    return hay.includes(q);
  });
  relFiltered.sort((a, b) => {
    const av = sortKey === "source" ? nameOf(a.source) : sortKey === "target" ? nameOf(a.target) : a.kind;
    const bv = sortKey === "source" ? nameOf(b.source) : sortKey === "target" ? nameOf(b.target) : b.kind;
    return String(av).localeCompare(String(bv)) || a.source.localeCompare(b.source);
  });

  if (!edges.length) {
    bodyEl.innerHTML = `<tr class="state-row"><td colspan="4">${stateHTML("empty", "No relationships in the graph")}</td></tr>`;
    renderPager(document.getElementById("relsPage"), 0, REL_PAGE_SIZE, 0, () => {});
    return;
  }
  if (!relFiltered.length) {
    bodyEl.innerHTML = `<tr class="state-row"><td colspan="4">${stateHTML("empty", "No relationships match the filter")}</td></tr>`;
    renderPager(document.getElementById("relsPage"), 0, REL_PAGE_SIZE, 0, () => {});
    return;
  }
  const total = relFiltered.length;
  const start = relPage * REL_PAGE_SIZE;
  const slice = relFiltered.slice(start, start + REL_PAGE_SIZE);
  bodyEl.innerHTML = slice.map((e, i) => `<tr class="clickable" data-rel="${start + i}">
    <td><strong>${esc(e.kind)}</strong></td>
    <td>${esc(nameOf(e.source))}</td>
    <td>${esc(nameOf(e.target))}</td>
    <td><span class="mono">${esc(JSON.stringify(e.props || {}))}</span></td></tr>`).join("");
  bodyEl.querySelectorAll("tr[data-rel]").forEach((tr) => {
    tr.addEventListener("click", () => {
      const e = relFiltered[parseInt(tr.dataset.rel, 10)];
      if (e) openEdgeModal(e);
    });
  });
  renderPager(document.getElementById("relsPage"), total, REL_PAGE_SIZE, start, (off) => {
    relPage = Math.floor(off / REL_PAGE_SIZE);
    renderRelationships();
  });
}

// ---------------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------------

async function loadAudit() {
  const bodyEl = document.getElementById("auditBody");
  if (!bodyEl) return;
  const limit = val("auditLimit") || "50";
  bodyEl.innerHTML = `<tr class="state-row"><td colspan="6">${stateHTML("loading", "Loading audit events…")}</td></tr>`;
  try {
    const j = await apiGet("/api/v1/audit?limit=" + encodeURIComponent(limit));
    const events = j.events || [];
    if (!events.length) {
      bodyEl.innerHTML = `<tr class="state-row"><td colspan="6">${stateHTML("empty", "No audit events recorded", "Write actions and denials are logged here.")}</td></tr>`;
      return;
    }
    bodyEl.innerHTML = events.map((e) => `<tr>
      <td><span class="mono">${esc(e.time || "")}</span></td>
      <td>${esc(e.actor || "")}</td>
      <td>${esc(e.action || "")}</td>
      <td>${esc(e.target || "")}</td>
      <td class="${e.result === "ok" ? "enabled" : "disabled"}">${esc(e.result || "")}</td>
      <td>${esc(e.reason || "")}</td></tr>`).join("");
  } catch (e) {
    bodyEl.innerHTML = `<tr class="state-row"><td colspan="6">${stateHTML("error", "Failed to load audit events", e.message)}</td></tr>`;
  }
}

// ---------------------------------------------------------------------------
// Ingestion
// ---------------------------------------------------------------------------

function populateIngestionCommands() {
  const origin = location.origin;
  const map = {
    collectorCmd: `omenhound collect --collector ldap --domain corp.local --server dc01 \\\n  --username svc_collect --password-stdin -c all --out graph.json`,
    importCmd: `omenhound import --in BloodHound_CE.zip --out graph.json`,
    pushCmd: `omenhound import --in BloodHound_CE.zip --api ${origin} --token $OMENHOUND_API_TOKEN`,
    serveCmd: `omenhound serve --neo4j-uri bolt://localhost:7687 --api-token $OMENHOUND_API_TOKEN`,
  };
  for (const id of Object.keys(map)) {
    const el = document.getElementById(id);
    if (el) el.textContent = map[id];
  }
}

function wireIngestion() {
  document.querySelectorAll(".ingestion-tabs .tab-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".ingestion-tabs .tab-btn").forEach((b) => b.classList.remove("active"));
      document.querySelectorAll(".tab-panel").forEach((p) => { p.hidden = true; p.classList.remove("active"); });
      btn.classList.add("active");
      const panel = document.getElementById("tab-" + btn.dataset.tab);
      if (panel) { panel.hidden = false; panel.classList.add("active"); }
    });
  });

  document.querySelectorAll(".copy-btn[data-target]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const target = document.getElementById(btn.dataset.target);
      if (!target) return;
      navigator.clipboard.writeText(target.textContent).then(() => {
        const old = btn.textContent;
        btn.textContent = "✓";
        btn.classList.add("copied");
        setTimeout(() => { btn.textContent = old; btn.classList.remove("copied"); }, 1500);
      }).catch(() => toast("Clipboard unavailable", "warn"));
    });
  });

  const ingestFileEl = document.getElementById("ingestFile");
  if (ingestFileEl) {
    ingestFileEl.addEventListener("change", () => {
      const file = ingestFileEl.files[0];
      const statusEl = document.getElementById("ingestStatus");
      if (file && statusEl) { statusEl.textContent = `Selected: ${file.name} (${Math.round(file.size / 1024)} KB)`; statusEl.className = "muted"; }
    });
  }

  const ingestSubmit = document.getElementById("ingestSubmit");
  if (ingestSubmit) {
    ingestSubmit.addEventListener("click", async () => {
      const fileEl = document.getElementById("ingestFile");
      const tokenEl = document.getElementById("ingestToken");
      const statusEl = document.getElementById("ingestStatus");
      const file = fileEl && fileEl.files ? fileEl.files[0] : null;
      const token = tokenEl ? tokenEl.value.trim() : "";
      if (!file || !token) {
        if (statusEl) { statusEl.textContent = "Select a Graph JSON file and provide an operator token."; statusEl.className = "warn"; }
        return;
      }
      if (statusEl) { statusEl.textContent = "Uploading…"; statusEl.className = "muted"; }
      try {
        const text = await file.text();
        const res = await fetch("/api/v1/ingest", {
          method: "POST",
          headers: { "Content-Type": "application/json", Authorization: "Bearer " + token },
          body: text,
        });
        const r = await res.json().catch(() => ({}));
        if (!res.ok) throw new Error(r.error || res.statusText);
        if (statusEl) { statusEl.textContent = `OK: ${r.nodes} nodes, ${r.edges} edges ingested`; statusEl.className = "success"; }
        operatorToken = token;
        setLock(true);
        toast(`Ingested ${r.nodes} nodes, ${r.edges} edges`, "success");
        if (prefs.autoRefresh) await refresh();
      } catch (err) {
        if (statusEl) { statusEl.textContent = "Error: " + err.message; statusEl.className = "warn"; }
        toast("Ingest failed: " + err.message, "error");
      }
    });
  }
}

// ---------------------------------------------------------------------------
// Path Explorer
// ---------------------------------------------------------------------------

let pathSrcSel = null, pathDstSel = null;

function populatePathOptions() {
  const kinds = statsCache && statsCache.kinds ? Object.keys(statsCache.kinds) : [...new Set(nodes.map((n) => n.kind))];
  const relTypes = [...new Set(edges.map((e) => e.kind))].sort();
  const nodeOptions = kinds.sort().map((k) => `<option value="${esc(k)}">${esc(k)}</option>`).join("");
  const relOptions = relTypes.map((k) => `<option value="${esc(k)}">${esc(k)}</option>`).join("");
  const includeNodes = document.getElementById("pathIncludeNodes");
  const excludeNodes = document.getElementById("pathExcludeNodes");
  const includeRels = document.getElementById("pathIncludeRels");
  const excludeRels = document.getElementById("pathExcludeRels");
  const keep = (el, html) => { if (el) { const sel = Array.from(el.selectedOptions).map((o) => o.value); el.innerHTML = html; Array.from(el.options).forEach((o) => { if (sel.indexOf(o.value) !== -1) o.selected = true; }); } };
  keep(includeNodes, nodeOptions);
  keep(excludeNodes, nodeOptions);
  keep(includeRels, relOptions);
  keep(excludeRels, relOptions);

  const note = document.getElementById("pathNote");
  if (note) note.textContent = "Backend executes a breadth-first shortest-path search. Dijkstra is not implemented server-side.";
  const algo = document.getElementById("pathAlgo");
  if (algo) {
    const opt = algo.querySelector('option[value="dijkstra"]');
    if (opt) { opt.disabled = true; opt.title = "Not implemented by the backend (BFS only)"; }
  }
}

function populatePathSuggestFromGraph() {
  const note = document.getElementById("pathNote");
  if (note && !edges.length) note.textContent = "No relationships loaded yet — ingest data first.";
}

function wirePathSuggest(inputId, resId, setter) {
  const input = document.getElementById(inputId);
  const res = document.getElementById(resId);
  if (!input || !res) return;
  let t = null;
  input.addEventListener("input", () => {
    clearTimeout(t);
    t = setTimeout(async () => {
      const q = input.value.trim();
      if (q.length < 2) { res.hidden = true; res.innerHTML = ""; return; }
      try {
        const j = await apiGet("/api/v1/objects?search=" + encodeURIComponent(q) + "&limit=10");
        const items = j.nodes || [];
        res.innerHTML = items.length
          ? items.map((n) => `<div class="suggest-item" data-id="${esc(n.id)}">${esc(nodeLabel(n))} <span class="kind">${esc(n.kind)}</span></div>`).join("")
          : '<div class="suggest-item muted">no matches</div>';
        res.hidden = false;
        res.querySelectorAll(".suggest-item[data-id]").forEach((el) => {
          el.addEventListener("click", () => {
            setter(el.dataset.id);
            input.value = el.textContent.trim();
            res.hidden = true;
            res.innerHTML = "";
          });
        });
      } catch (_) {
        res.hidden = true;
      }
    }, 200);
  });
  document.addEventListener("click", (ev) => {
    if (!res.contains(ev.target) && ev.target !== input) res.hidden = true;
  });
}

function wirePathExplorer() {
  wirePathSuggest("pathSrc", "pathSrcRes", (id) => { pathSrcSel = id; });
  wirePathSuggest("pathDst", "pathDstRes", (id) => { pathDstSel = id; });

  const btn = document.getElementById("pathSearch");
  if (btn) {
    btn.addEventListener("click", async () => {
      const results = document.getElementById("pathResults");
      if (!results) return;
      if (!pathSrcSel || !pathDstSel) {
        results.innerHTML = stateHTML("error", "Select a source and a destination", "Use the search boxes above; pick an object from the suggestions.");
        return;
      }
      results.innerHTML = stateHTML("loading", "Searching paths…");
      const body = {
        source_id: pathSrcSel,
        target_id: pathDstSel,
        max_depth: parseInt(val("pathDepth") || "5", 10),
        max_paths: parseInt(val("pathMax") || "10", 10),
        direction: val("pathDir") || "outgoing",
        include_node_types: Array.from(document.getElementById("pathIncludeNodes").selectedOptions).map((o) => o.value),
        exclude_node_types: Array.from(document.getElementById("pathExcludeNodes").selectedOptions).map((o) => o.value),
        include_relationship_types: Array.from(document.getElementById("pathIncludeRels").selectedOptions).map((o) => o.value),
        exclude_relationship_types: Array.from(document.getElementById("pathExcludeRels").selectedOptions).map((o) => o.value),
      };
      try {
        const res = await fetch("/api/v1/paths/shortest", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
        const j = await res.json().catch(() => ({}));
        if (!res.ok) throw new Error(j.error || res.statusText);
        const paths = j.paths || [];
        const note = document.getElementById("pathNote");
        if (note) note.textContent = j.truncated ? `Showing the first ${paths.length} paths (result truncated by max_paths).` : `${paths.length} path(s) found.`;
        if (!paths.length) {
          results.innerHTML = stateHTML("empty", "No paths found", "Try increasing max depth or changing the direction.");
          return;
        }
        results.innerHTML = paths.map((p, i) => {
          const nodeChips = (p.nodes || []).map((n, idx) => {
            const cls = idx === 0 ? "path-node source" : idx === (p.nodes.length - 1) ? "path-node target" : "path-node";
            const chip = `<span class="${cls}">${esc(nodeLabel(n))}</span>`;
            return idx === 0 ? chip : `<span class="path-arrow">→</span>${chip}`;
          }).join("");
          const relChips = (p.relationships || []).map((e) => `<span class="path-rel">${esc(e.kind)}</span>`).join("");
          return `<div class="path-item">
            <div class="path-header"><span class="path-length">len ${p.length}</span><span class="muted small">Path ${i + 1}</span></div>
            <div class="path-nodes">${nodeChips}</div>
            <div class="path-rels">${relChips}</div>
          </div>`;
        }).join("");
      } catch (e) {
        results.innerHTML = stateHTML("error", "Path search failed", e.message);
      }
    });
  }

  const clearBtn = document.getElementById("pathClear");
  if (clearBtn) {
    clearBtn.addEventListener("click", () => {
      const s = document.getElementById("pathSrc"), d = document.getElementById("pathDst"), r = document.getElementById("pathResults");
      if (s) s.value = "";
      if (d) d.value = "";
      if (r) r.innerHTML = "";
      pathSrcSel = null; pathDstSel = null;
      const note = document.getElementById("pathNote");
      if (note) note.textContent = "";
    });
  }
}

// ---------------------------------------------------------------------------
// Settings / About
// ---------------------------------------------------------------------------

async function loadAbout() {
  const dl = document.getElementById("aboutInfo");
  if (!dl) return;
  dl.innerHTML = `<dt>status</dt><dd>loading…</dd>`;
  try {
    const [health, stats] = await Promise.all([apiGet("/api/v1/health"), apiGet("/api/v1/stats").catch(() => null)]);
    const rows = [
      ["product", "OmenHound"],
      ["version", health.version],
      ["write_api", health.write_api_enabled ? "enabled" : "disabled"],
      ["credential_ops", health.credential_ops_enabled ? "enabled" : "disabled"],
      ["server_time", health.time],
    ];
    if (stats) {
      rows.push(["nodes", String(stats.nodes)]);
      rows.push(["edges", String(stats.edges)]);
    }
    dl.innerHTML = rows.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join("");
  } catch (e) {
    dl.innerHTML = `<dt>error</dt><dd>${esc(e.message)}</dd>`;
  }
}

function wireSettings() {
  const pairs = [
    ["settingLabels", "labels"],
    ["settingEdgeLabels", "edgeLabels"],
    ["settingLegend", "legend"],
    ["settingPhysics", "physics"],
    ["settingReduceMotion", "reduceMotion"],
    ["settingAutoRefresh", "autoRefresh"],
    ["settingPreserveSelection", "preserveSelection"],
  ];
  pairs.forEach(([id, key]) => {
    const el = document.getElementById(id);
    if (el) el.addEventListener("change", () => { prefs[key] = el.checked; savePrefs(); });
  });
  const interval = document.getElementById("settingRefreshInterval");
  if (interval) interval.addEventListener("change", () => { prefs.refreshInterval = parseInt(interval.value || "0", 10) || 0; savePrefs(); });
  const theme = document.getElementById("settingTheme");
  if (theme) theme.addEventListener("change", () => { prefs.theme = theme.value; savePrefs(); });
  const density = document.getElementById("settingDensity");
  if (density) density.addEventListener("change", () => { prefs.density = density.value; savePrefs(); });

  // Toolbar graph controls (share the same prefs).
  const labelToggle = document.getElementById("showLabels");
  if (labelToggle) labelToggle.addEventListener("change", () => { prefs.labels = labelToggle.checked; savePrefs(); });
  const edgeLabelToggle = document.getElementById("showEdgeLabels");
  if (edgeLabelToggle) edgeLabelToggle.addEventListener("change", () => { prefs.edgeLabels = edgeLabelToggle.checked; savePrefs(); });
  const legendToggle = document.getElementById("showLegend");
  if (legendToggle) legendToggle.addEventListener("change", () => { prefs.legend = legendToggle.checked; savePrefs(); });
}

// ---------------------------------------------------------------------------
// Write-API auth gate
// ---------------------------------------------------------------------------

const gate = document.getElementById("gate");

function setLock(unlocked) {
  const b = document.getElementById("push");
  if (!b) return;
  b.textContent = unlocked ? "🔓 Write API" : "🔒 Write API";
  b.classList.toggle("unlocked", unlocked);
}

function openGate() {
  if (!gate) return;
  const status = document.getElementById("gate-status");
  if (status) status.textContent = "";
  gate.hidden = false;
  const tokenInput = document.getElementById("gate-token");
  if (tokenInput) tokenInput.focus();
}
function closeGate() { if (gate) gate.hidden = true; }

function wireGate() {
  const pushBtn = document.getElementById("push");
  if (pushBtn) pushBtn.addEventListener("click", openGate);
  const gateCancel = document.getElementById("gate-cancel");
  if (gateCancel) gateCancel.addEventListener("click", closeGate);
  if (gate) gate.addEventListener("keydown", (ev) => { if (ev.key === "Escape") closeGate(); });

  const gatePush = document.getElementById("gate-push");
  if (gatePush) {
    gatePush.addEventListener("click", async () => {
      const tokenEl = document.getElementById("gate-token");
      const bodyEl = document.getElementById("gate-json");
      const status = document.getElementById("gate-status");
      const token = tokenEl ? tokenEl.value.trim() : "";
      const body = bodyEl ? bodyEl.value.trim() : "";
      if (!status) return;
      if (!token || !body) {
        status.className = "warn";
        status.textContent = "an operator token and graph JSON are both required";
        return;
      }
      status.className = "muted";
      status.textContent = "pushing…";
      try {
        const res = await fetch("/api/v1/ingest", {
          method: "POST",
          headers: { "Content-Type": "application/json", Authorization: "Bearer " + token },
          body,
        });
        const r = await res.json().catch(() => ({}));
        if (!res.ok) {
          status.className = "warn";
          status.textContent = `denied: ${r.error || res.statusText}`;
          return;
        }
        operatorToken = token;
        setLock(true);
        status.className = "muted";
        status.textContent = `ok: ${r.nodes} nodes, ${r.edges} edges ingested`;
        await refresh();
      } catch (err) {
        status.className = "warn";
        status.textContent = "error: " + err.message;
      }
    });
  }
}

// ---------------------------------------------------------------------------
// Global search
// ---------------------------------------------------------------------------

let searchIndex = [];
let searchActive = -1;

function wireGlobalSearch() {
  const searchEl = document.getElementById("search");
  const clearBtn = document.getElementById("searchClear");
  const resultsEl = document.getElementById("searchResults");
  if (!searchEl || !resultsEl) return;
  let t = null;

  const closeResults = () => { resultsEl.hidden = true; resultsEl.innerHTML = ""; searchIndex = []; searchActive = -1; };

  searchEl.addEventListener("input", () => {
    clearTimeout(t);
    const q = searchEl.value.trim();
    if (clearBtn) clearBtn.hidden = q === "";
    if (q.length < 2) { applyFilters(); closeResults(); return; }
    t = setTimeout(async () => {
      try {
        const j = await apiGet("/api/v1/objects?search=" + encodeURIComponent(q) + "&limit=10");
        searchIndex = j.nodes || [];
        searchActive = -1;
        resultsEl.innerHTML = searchIndex.length
          ? searchIndex.map((n, i) => `<div class="search-result" role="option" data-i="${i}"><span class="kind-badge" style="background:${COLORS[n.kind] || "#888"};color:#0b0e14">${esc(n.kind)}</span><span class="sr-name">${esc(nodeLabel(n))}</span><span class="sr-id">${esc(n.id.slice(0, 24))}</span></div>`).join("")
          : '<div class="search-result-empty">no matches</div>';
        resultsEl.hidden = false;
        resultsEl.querySelectorAll(".search-result[data-i]").forEach((el) => {
          el.addEventListener("click", () => { openObject(searchIndex[parseInt(el.dataset.i, 10)].id); closeResults(); if (searchEl) searchEl.blur(); });
        });
      } catch (_) {
        resultsEl.hidden = true;
      }
      applyFilters();
    }, 200);
  });

  searchEl.addEventListener("keydown", (ev) => {
    const items = resultsEl.querySelectorAll(".search-result[data-i]");
    if (ev.key === "ArrowDown" && items.length) {
      ev.preventDefault();
      searchActive = (searchActive + 1) % items.length;
      items.forEach((el, i) => el.classList.toggle("active", i === searchActive));
    } else if (ev.key === "ArrowUp" && items.length) {
      ev.preventDefault();
      searchActive = (searchActive - 1 + items.length) % items.length;
      items.forEach((el, i) => el.classList.toggle("active", i === searchActive));
    } else if (ev.key === "Enter") {
      ev.preventDefault();
      if (searchActive >= 0 && searchIndex[searchActive]) openObject(searchIndex[searchActive].id);
      else if (searchIndex.length) openObject(searchIndex[0].id);
      closeResults();
    } else if (ev.key === "Escape") {
      closeResults();
    }
  });

  if (clearBtn) {
    clearBtn.addEventListener("click", () => {
      searchEl.value = "";
      clearBtn.hidden = true;
      closeResults();
      applyFilters();
    });
  }
  document.addEventListener("click", (ev) => {
    if (!resultsEl.contains(ev.target) && ev.target !== searchEl) closeResults();
  });
}

// ---------------------------------------------------------------------------
// Wiring & init
// ---------------------------------------------------------------------------

function wireToolbar() {
  const fitViewBtn = document.getElementById("fitView");
  if (fitViewBtn) fitViewBtn.addEventListener("click", fitView);
  const resetViewBtn = document.getElementById("resetView");
  if (resetViewBtn) resetViewBtn.addEventListener("click", resetView);
  const centerSelectionBtn = document.getElementById("centerSelection");
  if (centerSelectionBtn) centerSelectionBtn.addEventListener("click", centerSelection);
  const reloadEl = document.getElementById("reload");
  if (reloadEl) reloadEl.addEventListener("click", () => refresh().then(() => toast("Graph reloaded", "success")).catch((e) => toast("Reload failed: " + e.message, "error")));

  const nodeKindFilter = document.getElementById("nodeKindFilter");
  if (nodeKindFilter) nodeKindFilter.addEventListener("change", () => { applyFilters(); fitView(); });
  const edgeKindFilter = document.getElementById("edgeKindFilter");
  if (edgeKindFilter) edgeKindFilter.addEventListener("change", () => { applyFilters(); });

  const openInGraph = document.getElementById("openInGraph");
  if (openInGraph) openInGraph.addEventListener("click", () => { if (selectedNode) centerSelection(); });

  const panelClose = document.getElementById("panelClose");
  if (panelClose) panelClose.addEventListener("click", clearSelection);

  const copyCommandBtn = document.getElementById("copyCommand");
  if (copyCommandBtn) {
    copyCommandBtn.addEventListener("click", () => {
      const pre = document.getElementById("edge-command");
      if (pre && navigator.clipboard) navigator.clipboard.writeText(pre.textContent).catch(() => {});
    });
  }
  const copyAltsBtn = document.getElementById("copyAlts");
  if (copyAltsBtn) {
    copyAltsBtn.addEventListener("click", () => {
      const pre = document.getElementById("edge-alts");
      if (pre && navigator.clipboard) navigator.clipboard.writeText(pre.textContent).catch(() => {});
    });
  }

  // Sidebar collapse.
  const sidebarToggle = document.getElementById("sidebarToggle");
  const sidebar = document.getElementById("sidebar");
  if (sidebarToggle && sidebar) {
    sidebarToggle.addEventListener("click", () => {
      if (window.innerWidth <= 768) {
        sidebar.classList.toggle("open");
        overlay.classList.toggle("visible");
      } else {
        sidebar.classList.toggle("collapsed");
        setTimeout(resize, 200);
      }
    });
  }

  const domainSel = document.getElementById("domainSelect");
  if (domainSel) {
    domainSel.addEventListener("change", (e) => {
      currentDomain = e.target.value;
      const active = document.querySelector(".nav-btn.active");
      const v = active ? active.dataset.view : "";
      if (["users", "groups", "computers", "ous", "gpos", "containers"].indexOf(v) !== -1) loadTable(v, 0);
      else if (v === "relationships") renderRelationships();
    });
  }

  const auditRefresh = document.getElementById("auditRefresh");
  if (auditRefresh) auditRefresh.addEventListener("click", loadAudit);
  const auditLimit = document.getElementById("auditLimit");
  if (auditLimit) auditLimit.addEventListener("change", loadAudit);

  // Modal wiring.
  const objClose = document.getElementById("objClose");
  if (objClose) objClose.addEventListener("click", closeObjectModal);
  const objCloseIcon = document.getElementById("objCloseIcon");
  if (objCloseIcon) objCloseIcon.addEventListener("click", closeObjectModal);
  const objOpenGraph = document.getElementById("objOpenGraph");
  if (objOpenGraph) objOpenGraph.addEventListener("click", modalOpenInGraph);
  const objFindPath = document.getElementById("objFindPath");
  if (objFindPath) objFindPath.addEventListener("click", modalFindPaths);
  const objectModal = document.getElementById("objectModal");
  if (objectModal) {
    objectModal.addEventListener("click", (ev) => { if (ev.target === objectModal) closeObjectModal(); });
    objectModal.addEventListener("keydown", (ev) => { if (ev.key === "Escape") closeObjectModal(); });
  }

  // Domain list search.
  const domainSearch = document.getElementById("domainSearch");
  if (domainSearch) domainSearch.addEventListener("input", () => loadDomains());
}

const overlay = document.createElement("div");
overlay.className = "sidebar-overlay";
document.body.appendChild(overlay);
overlay.addEventListener("click", () => {
  const sidebar = document.getElementById("sidebar");
  if (sidebar) sidebar.classList.remove("open");
  overlay.classList.remove("visible");
});

async function refresh() {
  await loadGraph();
  populateDynamicFilters();
  await loadDomains();
  setLock(!!operatorToken);
  const active = parseHash();
  // Refresh effort for the currently-visible data view.
  if (["users", "groups", "computers", "ous", "gpos", "containers"].indexOf(active) !== -1) loadTable(active, 0);
  else if (active === "relationships") renderRelationships();
  else if (active === "overview") loadOverview();
}

function init() {
  loadPrefs();
  try { resize(); } catch (_) {}
  attachNav();
  wireToolbar();
  wireTableControls();
  wireSettings();
  wireGate();
  wireIngestion();
  wirePathExplorer();
  wireGlobalSearch();

  const startView = parseHash();
  renderView(startView);

  refresh().then(() => {
    settleLayout();
    try { loop(); } catch (_) {}
    renderView(startView);
  }).catch(() => {
    try { loop(); } catch (_) {}
  });
  scheduleAutoRefresh();
}

// Keyboard shortcuts (ignored while typing in a form control).
document.addEventListener("keydown", (e) => {
  const tag = e.target && e.target.tagName;
  if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT" || e.target.isContentEditable) return;
  switch (e.key) {
    case "f": fitView(); break;
    case "r": resetView(); break;
    case "c": centerSelection(); break;
    case "Escape":
      if (gate && !gate.hidden) closeGate();
      else closeObjectModal();
      break;
  }
});

try { attachNav(); } catch (_) {}
if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", init);
} else {
  init();
}

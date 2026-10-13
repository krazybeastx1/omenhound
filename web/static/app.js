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
  arrows: true,
  tooltips: true,
  reduceMotion: false,
  autoRefresh: true,
  preserveSelection: true,
  refreshInterval: 0,
  theme: "dark",
  density: "comfortable",
};

// Force-directed layout tuning (Fruchterman–Reingold style). Distances are in
// world units; the view transform maps world -> screen. `temp` (temperature)
// bounds how far a node may move per iteration and cools to 0 when the layout
// settles, at which point the animation loop stops entirely.
const LAYOUT = {
  ideal: 78,        // ideal edge length / node spacing
  cutoffMul: 9,     // approximate repulsion cutoff = ideal * cutoffMul
  cooling: 0.985,   // temperature decay per iteration
  minTemp: 0.4,     // below this the simulation is considered stable
  maxIter: 3,       // simulation iterations per animation frame
  settleIters: 450, // fast-forward iterations on load / re-layout
  gravity: 0.008,   // pull toward origin so components do not drift apart
  collidePad: 12,   // extra world units kept between node discs
};

// Base radius per node kind (world units), scaled by degree in loadGraph.
const NODE_RADIUS = {
  Domain: 12, Container: 7, Computer: 9, User: 8, Group: 8,
  GPO: 8, OU: 8, Trust: 9, Base: 6,
};

// Session evidence is the BloodHound `HasSession` edge: (User)-[:HasSession]->(Computer).
// OmenHound's collectors emit it with no properties, so the UI never asserts a
// timestamp or an observed/historical/stale status it cannot prove.
const SESSION_EDGE = "HasSession";

// Optional, backward-compatible credential-evidence namespace for node props.
//
// A collector *may* attach keys prefixed `cred.` to a node to describe a
// credential reference, e.g.:
//
//   cred.type        password | nthash | ntlm | kerberos-ticket | token | certificate
//   cred.source      where the reference came from (collector / import)
//   cred.ref         an opaque fingerprint or reference id — NEVER the raw secret
//   cred.observed_at RFC3339 collection timestamp
//   cred.status      discovered | imported | validated | expired | unknown
//
// Values are treated as sensitive references and are masked by default. No
// shipped OmenHound collector emits these keys, so the Credentials panel
// normally renders its honest empty state; the namespace exists so a future
// importer can surface evidence without inventing it.
const CRED_PREFIX = "cred.";

// ---------------------------------------------------------------------------
// Element handles & graph state
// ---------------------------------------------------------------------------

const canvas = document.getElementById("graph");
const ctx = canvas ? canvas.getContext("2d") : null;

let nodes = [];
let edges = [];
let byId = new Map();
let adjacency = new Map();      // id -> { out: [], in: [], neighbors: [] }
let temp = 0;                   // simulation temperature (0 == stable)
let selectedNode = null;
let selectedEdge = null;
let hoverNode = null;
let hoverEdge = null;
let isolateMode = false;        // show only the selected node + neighbours
let hideUnrelatedEdges = false; // dim edges not incident to the selection
let matchIds = new Set();       // node ids highlighted by the graph search
let screenIndex = new Map();    // screen-space grid, rebuilt in draw() for hit tests
let startNodeId = null;         // analysis origin — deliberately separate from selection
let targetNodeId = null;        // path destination — deliberately separate from selection
let sessionsOnly = false;       // filter: show only observed-session relationships
let pathHighlight = null;       // { nodes:Set, edges:Set } highlighted from Path Explorer

// view transform: screen = world * k + (x, y)
let view = { x: 0, y: 0, k: 1 };

const drag = { node: null, panning: false, moved: false, sx: 0, sy: 0, ox: 0, oy: 0, pin: false };

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
  set("showArrows", prefs.arrows);
  set("settingLabels", prefs.labels);
  set("settingEdgeLabels", prefs.edgeLabels);
  set("settingLegend", prefs.legend);
  set("settingArrows", prefs.arrows);
  set("settingTooltips", prefs.tooltips);
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
  requestRender();
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
  // Measure the canvas' own box (CSS drives its size via flex), never the
  // parent's — the parent also contains the Inspector panel.
  const w = canvas.clientWidth, h = canvas.clientHeight;
  if (w === 0 || h === 0) return;
  const dpr = window.devicePixelRatio || 1;
  const bw = Math.round(w * dpr), bh = Math.round(h * dpr);
  if (canvas.width !== bw || canvas.height !== bh) {
    canvas.width = bw;
    canvas.height = bh;
  }
  if (ctx) ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  requestRender();
}
let resizeRaf = null;
window.addEventListener("resize", () => {
  if (resizeRaf) return;
  resizeRaf = requestAnimationFrame(() => { resizeRaf = null; resize(); });
});
if (typeof ResizeObserver !== "undefined" && canvas && canvas.parentElement) {
  try { new ResizeObserver(() => resize()).observe(canvas.parentElement); } catch (_) { /* ignore */ }
}

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

function nodeHidden(n) {
  if (n.hidden === true) return true;
  // Sessions-only filter: keep only identities/hosts that have a session edge.
  if (sessionsOnly && !nodeHasSession(n.id)) return true;
  return false;
}

// True when the node participates in at least one observed-session edge.
function nodeHasSession(id) {
  const rec = adjacency.get(id);
  if (!rec) return false;
  return rec.out.some((e) => e.kind === SESSION_EDGE) || rec.in.some((e) => e.kind === SESSION_EDGE);
}

function edgeHidden(e) {
  const ek = val("edgeKindFilter");
  if (ek && e.kind !== ek) return true;
  if (sessionsOnly && e.kind !== SESSION_EDGE) return true;
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
    const count = Math.max(1, rawNodes.length);
    // Golden-angle spiral start: nodes begin evenly spread rather than on one
    // tiny circle, so they no longer explode into a single dense cluster.
    const radius = 40 + count * 3;
    nodes = rawNodes.map((n, i) => {
      const prior = old.get(n.id);
      const t = i * 2.39996323; // golden angle
      const rr = Math.sqrt((i + 0.5) / count) * radius;
      return {
        ...n,
        kind: n.kind || "Base",
        x: prior ? prior.x : Math.cos(t) * rr,
        y: prior ? prior.y : Math.sin(t) * rr,
        vx: 0, vy: 0,
        fixed: prior ? !!prior.fixed : false,
        r: NODE_RADIUS[n.kind] || 8,
        hidden: false,
        dim: false,
        match: false,
      };
    });
    edges = (g.edges || []).map((e) => ({ ...e, source: String(e.source), target: String(e.target), kind: e.kind || "Related" }));
    byId = new Map(nodes.map((n) => [n.id, n]));
    edges = edges.filter((e) => byId.has(e.source) && byId.has(e.target));

    buildAdjacency();

    // Size nodes by degree so hubs stand out, and re-heat the simulation.
    for (const n of nodes) {
      const deg = degreeOf(n.id);
      n.r = (NODE_RADIUS[n.kind] || 8) * (1 + Math.min(1, deg / 14) * 0.7);
    }
    isolateMode = false;
    temp = Math.max(40, (canvas ? canvas.clientWidth : 900) / 7);

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

// Build the adjacency index once per load so the Inspector, neighbour
// highlighting and isolation answer in O(1) instead of scanning every edge.
function buildAdjacency() {
  adjacency = new Map();
  for (const n of nodes) adjacency.set(n.id, { out: [], in: [], neighbors: [] });
  for (const e of edges) {
    const a = adjacency.get(e.source), b = adjacency.get(e.target);
    if (a) a.out.push(e);
    if (b) b.in.push(e);
  }
  for (const [id, rec] of adjacency) {
    const set = new Set();
    for (const e of rec.out) set.add(e.target);
    for (const e of rec.in) set.add(e.source);
    set.delete(id);
    rec.neighbors = [...set];
  }
}

function degreeOf(id) {
  const rec = adjacency.get(id);
  return rec ? rec.out.length + rec.in.length : 0;
}

// The node plus its direct neighbours (used for highlight and isolation).
function neighborhood(node) {
  const ids = new Set([node.id]);
  const rec = adjacency.get(node.id);
  if (rec) for (const nid of rec.neighbors) ids.add(nid);
  return ids;
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
  if (cats.length && prefs.arrows) {
    html += `<span class="legend-group">Direction</span><span class="edge-legend"><i class="legend-arrow"></i>source → target</span>`;
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

// ---- spatial grid (approximate repulsion + collision) ----

function buildGrid(list, cell) {
  const g = new Map();
  for (const n of list) {
    const key = Math.floor(n.x / cell) + "|" + Math.floor(n.y / cell);
    let bucket = g.get(key);
    if (!bucket) { bucket = []; g.set(key, bucket); }
    bucket.push(n);
  }
  return { g, cell };
}

function gridNeighbors(grid, n) {
  const { g, cell } = grid;
  const cx = Math.floor(n.x / cell), cy = Math.floor(n.y / cell);
  const out = [];
  for (let i = -1; i <= 1; i++) {
    for (let j = -1; j <= 1; j++) {
      const bucket = g.get((cx + i) + "|" + (cy + j));
      if (bucket) for (const o of bucket) out.push(o);
    }
  }
  return out;
}

// One Fruchterman–Reingold iteration. Repulsion is limited to a neighbourhood
// cutoff via the spatial grid, so the cost scales with density rather than
// O(n^2) — hundreds/thousands of nodes stay interactive.
function step() {
  const vis = visibleNodes();
  const n = vis.length;
  if (n === 0) return;
  const k = LAYOUT.ideal;
  const cutoff = k * LAYOUT.cutoffMul;
  const cutoff2 = cutoff * cutoff;
  const grid = buildGrid(vis, cutoff);
  const disp = new Map();
  for (const node of vis) disp.set(node, { x: 0, y: 0 });

  // 1. repulsive forces (k^2 / d)
  for (const node of vis) {
    const out = disp.get(node);
    for (const other of gridNeighbors(grid, node)) {
      if (other === node) continue;
      let dx = node.x - other.x, dy = node.y - other.y;
      let d2 = dx * dx + dy * dy;
      if (d2 > cutoff2) continue;
      if (d2 < 0.01) { dx = Math.random() - 0.5; dy = Math.random() - 0.5; d2 = 0.01; }
      const d = Math.sqrt(d2);
      const f = (k * k) / d;
      out.x += (dx / d) * f;
      out.y += (dy / d) * f;
    }
  }

  // 2. attractive forces (d^2 / k) along real relationships
  for (const e of edges) {
    if (edgeHidden(e)) continue;
    const a = byId.get(e.source), b = byId.get(e.target);
    if (!a || !b || nodeHidden(a) || nodeHidden(b)) continue;
    const da = disp.get(a), db = disp.get(b);
    if (!da || !db) continue;
    let dx = a.x - b.x, dy = a.y - b.y;
    const d = Math.sqrt(dx * dx + dy * dy) || 0.01;
    const f = (d * d) / k;
    const fx = (dx / d) * f, fy = (dy / d) * f;
    da.x -= fx; da.y -= fy; db.x += fx; db.y += fy;
  }

  // 3. weak gravity toward the origin keeps disconnected parts together
  for (const node of vis) {
    const out = disp.get(node);
    out.x -= node.x * LAYOUT.gravity * k;
    out.y -= node.y * LAYOUT.gravity * k;
  }

  // 4. integrate, bounded by temperature; pinned nodes never move
  for (const node of vis) {
    if (node.fixed) continue;
    const out = disp.get(node);
    const mag = Math.hypot(out.x, out.y) || 0.01;
    const lim = Math.min(mag, temp) / mag;
    node.x += out.x * lim;
    node.y += out.y * lim;
  }

  resolveCollisions(vis, grid);
  temp *= LAYOUT.cooling;
}

// Push overlapping discs apart so labels/entities never stack on one spot.
function resolveCollisions(vis, grid) {
  for (const node of vis) {
    for (const other of gridNeighbors(grid, node)) {
      if (other === node) continue;
      let dx = node.x - other.x, dy = node.y - other.y;
      let d2 = dx * dx + dy * dy;
      const minD = node.r + other.r + LAYOUT.collidePad;
      if (d2 >= minD * minD) continue;
      if (d2 < 0.01) { dx = Math.random() - 0.5; dy = Math.random() - 0.5; d2 = 0.01; }
      const d = Math.sqrt(d2);
      const push = (minD - d) * 0.5;
      const ux = dx / d, uy = dy / d;
      if (!node.fixed) { node.x += ux * push; node.y += uy * push; }
      if (!other.fixed) { other.x -= ux * push; other.y -= uy * push; }
    }
  }
}

// ---- label helpers ----

function truncate(s, n) {
  s = String(s == null ? "" : s);
  return s.length > n ? s.slice(0, n - 1) + "…" : s;
}

function roundRect(c, x, y, w, h, r) {
  const rr = Math.min(r, w / 2, h / 2);
  c.beginPath();
  c.moveTo(x + rr, y);
  c.arcTo(x + w, y, x + w, y + h, rr);
  c.arcTo(x + w, y + h, x, y + h, rr);
  c.arcTo(x, y + h, x, y, rr);
  c.arcTo(x, y, x + w, y, rr);
  c.closePath();
}

// Draw a translucent plate behind text so labels stay readable over edges.
function labelPlate(c, x, y, text, align) {
  const wpx = c.measureText(text).width;
  const pad = 3;
  const left = align === "left" ? x - pad : x - wpx / 2 - pad;
  c.save();
  c.globalAlpha *= 0.78;
  c.fillStyle = "rgba(9,13,20,0.92)";
  roundRect(c, left, y - 7, wpx + pad * 2, 14, 4);
  c.fill();
  c.restore();
}

function drawArrow(c, ax, ay, bx, by, color, alpha) {
  const dx = bx - ax, dy = by - ay;
  const d = Math.hypot(dx, dy) || 1;
  const ux = dx / d, uy = dy / d;
  const s = Math.max(6, Math.min(12, 7 * Math.max(0.6, Math.min(1.8, view.k))));
  const tipX = bx - ux * s * 0.9, tipY = by - uy * s * 0.9;
  const px = -uy, py = ux;
  c.save();
  c.globalAlpha = Math.max(0, Math.min(1, alpha));
  c.fillStyle = color;
  c.beginPath();
  c.moveTo(tipX + ux * s * 0.9, tipY + uy * s * 0.9);
  c.lineTo(tipX + px * s * 0.5, tipY + py * s * 0.5);
  c.lineTo(tipX - px * s * 0.5, tipY - py * s * 0.5);
  c.closePath();
  c.fill();
  c.restore();
}

// Draw the small S/T badge used to mark the starting / target node. Shape + text
// carry the meaning, so it survives greyscale and colour-blind rendering.
function drawMarkerBadge(c, x, y, r, letter, color) {
  const bx = x - r - 11, by = y - r - 11;
  c.save();
  c.beginPath();
  c.arc(bx, by, 7, 0, Math.PI * 2);
  c.fillStyle = "#0b0e14";
  c.fill();
  c.lineWidth = 1.6;
  c.strokeStyle = color;
  c.stroke();
  c.fillStyle = color;
  c.font = "bold 9px ui-sans-serif,system-ui,sans-serif";
  c.textAlign = "center";
  c.textBaseline = "middle";
  c.fillText(letter, bx, by + 0.5);
  c.restore();
}

function draw() {
  if (!canvas || !ctx || !canvas.parentElement) return;
  const w = canvas.clientWidth, h = canvas.clientHeight;
  if (w === 0 || h === 0) return;
  ctx.clearRect(0, 0, w, h);

  // Highlight set: the selected node's neighbourhood, or an edge's endpoints.
  let focus = null;
  if (selectedNode) focus = neighborhood(selectedNode);
  else if (selectedEdge) focus = new Set([selectedEdge.source, selectedEdge.target]);

  const k = view.k;

  // Project every visible node once and build a screen-space grid for hit tests.
  screenIndex = new Map();
  const cellSize = 32;
  for (const node of nodes) {
    if (nodeHidden(node)) { node._sx = null; continue; }
    const p = toScreen(node);
    node._sx = p.x; node._sy = p.y;
    node._sr = Math.max(3.5, node.r * k);
    const key = Math.floor(p.x / cellSize) + "|" + Math.floor(p.y / cellSize);
    let bucket = screenIndex.get(key);
    if (!bucket) { bucket = []; screenIndex.set(key, bucket); }
    bucket.push(node);
  }
  screenIndex._cell = cellSize;

  // ---- edges ----
  ctx.lineCap = "round";
  for (const e of edges) {
    if (edgeHidden(e)) continue;
    const a = byId.get(e.source), b = byId.get(e.target);
    if (!a || !b || a._sx == null || b._sx == null) continue;
    const ax = a._sx, ay = a._sy, bx = b._sx, by = b._sy;
    if (Math.max(ax, bx) < -40 || Math.min(ax, bx) > w + 40 || Math.max(ay, by) < -40 || Math.min(ay, by) > h + 40) continue;

    const isSel = selectedEdge === e;
    const isHover = hoverEdge === e;
    const incident = !!selectedNode && (e.source === selectedNode.id || e.target === selectedNode.id);
    const onPath = inPathEdges(e);
    const highlighted = isSel || isHover || incident || onPath || (focus && focus.has(e.source) && focus.has(e.target));
    let dimmed = (focus && !highlighted) || (hideUnrelatedEdges && !incident && !isSel);
    // While a path is highlighted, fade everything off the path.
    if (pathHighlight && !onPath) dimmed = true;

    ctx.strokeStyle = isSel ? "#ffffff" : onPath ? "#ffd600" : edgeColor(e.kind);
    ctx.lineWidth = onPath ? 3.4 : isSel ? 2.6 : isHover ? 2.2 : incident ? 1.8 : 1.1;
    ctx.globalAlpha = dimmed ? 0.05 : (isSel || isHover || incident || onPath) ? 0.95 : 0.42;
    ctx.beginPath();
    ctx.moveTo(ax, ay);
    ctx.lineTo(bx, by);
    ctx.stroke();

    if (prefs.arrows && (highlighted || (!dimmed && k >= 1.6))) {
      drawArrow(ctx, ax, ay, bx, by, ctx.strokeStyle, (isSel || isHover || incident) ? 0.95 : 0.4);
    }
  }
  ctx.globalAlpha = 1;

  // ---- edge labels (only relevant / zoomed; capped) ----
  const edgeBudget = (prefs.edgeLabels && k >= 0.9) || k >= 2.2 ? 60 : 0;
  let edgeLabelsDrawn = 0;
  ctx.font = "10px ui-sans-serif,system-ui,sans-serif";
  ctx.textAlign = "center";
  ctx.textBaseline = "middle";
  for (const e of edges) {
    if (edgeHidden(e)) continue;
    const isSel = selectedEdge === e, isHover = hoverEdge === e;
    if (!isSel && !isHover && edgeLabelsDrawn >= edgeBudget) continue;
    const a = byId.get(e.source), b = byId.get(e.target);
    if (!a || !b || a._sx == null || b._sx == null) continue;
    edgeLabelsDrawn++;
    const mx = (a._sx + b._sx) / 2, my = (a._sy + b._sy) / 2;
    const text = truncate(e.kind, 24);
    labelPlate(ctx, mx, my, text);
    ctx.fillStyle = isSel ? "#ffffff" : "rgba(226,232,240,0.95)";
    ctx.fillText(text, mx, my);
  }

  // ---- nodes ----
  for (const node of nodes) {
    if (node._sx == null) continue;
    const p = { x: node._sx, y: node._sy };
    if (p.x < -40 || p.x > w + 40 || p.y < -40 || p.y > h + 40) continue;
    const r = node._sr;
    const isSel = selectedNode === node;
    const isHover = hoverNode === node;
    const isMatch = matchIds.has(node.id);
    const onPath = inPathNodes(node.id);
    let dim = (focus && !focus.has(node.id)) || (node.dim && !isSel && !isHover);
    if (pathHighlight && !onPath) dim = true;

    ctx.globalAlpha = dim ? 0.12 : 1;
    ctx.beginPath();
    ctx.arc(p.x, p.y, r, 0, Math.PI * 2);
    ctx.fillStyle = COLORS[node.kind] || "#888";
    ctx.fill();

    if (isSel || isHover || isMatch) {
      ctx.lineWidth = isSel ? 3 : 2;
      ctx.strokeStyle = isSel ? "#ffffff" : isMatch ? "#ffd600" : "#cbd5e1";
      ctx.beginPath();
      ctx.arc(p.x, p.y, r + 3, 0, Math.PI * 2);
      ctx.stroke();
    } else if (node.fixed) {
      ctx.lineWidth = 1.5;
      ctx.strokeStyle = "rgba(255,255,255,0.5)";
      ctx.beginPath();
      ctx.arc(p.x, p.y, r + 2, 0, Math.PI * 2);
      ctx.stroke();
    }

    // Starting / target markers use a distinct SHAPE and a letter label, so the
    // meaning never depends on colour alone (accessible in greyscale too).
    if (node.id === startNodeId) {
      ctx.globalAlpha = 1;
      ctx.strokeStyle = "#00d4ff";
      ctx.lineWidth = 2.5;
      ctx.beginPath(); ctx.arc(p.x, p.y, r + 5, 0, Math.PI * 2); ctx.stroke();
      ctx.beginPath(); ctx.arc(p.x, p.y, r + 8, 0, Math.PI * 2); ctx.stroke();
      drawMarkerBadge(ctx, p.x, p.y, r, "S", "#00d4ff");
    }
    if (node.id === targetNodeId) {
      ctx.globalAlpha = 1;
      ctx.strokeStyle = "#ff8c42";
      ctx.lineWidth = 2.5;
      ctx.setLineDash([4, 3]);
      ctx.beginPath(); ctx.arc(p.x, p.y, r + 6, 0, Math.PI * 2); ctx.stroke();
      ctx.setLineDash([]);
      drawMarkerBadge(ctx, p.x, p.y, r, "T", "#ff8c42");
    }
    ctx.globalAlpha = 1;
  }

  // ---- node labels ----
  const wantAll = prefs.labels && k >= 1.15;
  const labelList = [];
  for (const node of nodes) {
    if (node._sx == null) continue;
    const isSel = selectedNode === node, isHover = hoverNode === node;
    const isNeighbor = focus && focus.has(node.id) && !isSel;
    const isMatch = matchIds.has(node.id);
    const important = isSel || isHover || isMatch || isNeighbor;
    if (!important && (!wantAll || node.dim || (focus && !focus.has(node.id)))) continue;
    labelList.push({ node, important, deg: degreeOf(node.id) });
  }
  labelList.sort((a, b) => (a.important === b.important ? b.deg - a.deg : a.important ? 1 : -1));
  const cap = k >= 2 ? 250 : 70;
  let drawn = 0;
  ctx.font = "11px ui-sans-serif,system-ui,sans-serif";
  ctx.textAlign = "left";
  ctx.textBaseline = "middle";
  for (const item of labelList) {
    if (!item.important && drawn >= cap) break;
    drawn++;
    const node = item.node;
    const text = truncate(nodeLabel(node), k >= 1.4 ? 34 : 24);
    const tx = node._sx + node._sr + 4, ty = node._sy;
    labelPlate(ctx, tx, ty, text, "left");
    ctx.fillStyle = item.important ? "#f1f5f9" : "rgba(226,232,240,0.85)";
    ctx.fillText(text, tx, ty);
  }
  ctx.textAlign = "start";
  ctx.textBaseline = "alphabetic";
}

// ---- animation loop (runs only while the layout is hot or on interaction) ----

let rafId = null;

function requestRender() {
  if (rafId === null && typeof requestAnimationFrame !== "undefined") rafId = requestAnimationFrame(frame);
}

function frame() {
  rafId = null;
  let stepped = false;
  if (prefs.physics && temp > LAYOUT.minTemp && nodes.length) {
    const iters = nodes.length > 800 ? 1 : LAYOUT.maxIter;
    for (let i = 0; i < iters; i++) {
      step();
      if (temp <= LAYOUT.minTemp) break;
    }
    stepped = true;
  }
  draw();
  if (stepped && temp > LAYOUT.minTemp) requestRender();
}

// Fast-forward the simulation off the animation clock for the initial view.
function settleLayout() {
  if (!nodes.length) { temp = 0; draw(); return; }
  const iters = nodes.length > 1500 ? 140 : LAYOUT.settleIters;
  for (let i = 0; i < iters; i++) {
    step();
    if (temp <= LAYOUT.minTemp) break;
  }
  temp = 0;
  draw();
}

// Re-run the layout from scratch: unpin nodes and reseed positions on a spiral.
function restartLayout() {
  const count = Math.max(1, nodes.length);
  const radius = 40 + count * 3;
  nodes.forEach((n, i) => {
    const t = i * 2.39996323;
    const rr = Math.sqrt((i + 0.5) / count) * radius;
    n.x = Math.cos(t) * rr;
    n.y = Math.sin(t) * rr;
    n.vx = 0; n.vy = 0; n.fixed = false;
  });
  temp = Math.max(40, (canvas ? canvas.clientWidth : 900) / 7);
  requestRender();
}

// ---- interaction ----

// Screen-space hit test using the grid rebuilt by draw(). Searches a 5x5 cell
// window so large and overlapping nodes stay reliably clickable.
function hitNode(sx, sy) {
  if (!screenIndex || screenIndex.size === 0) return null;
  const cell = screenIndex._cell || 32;
  const cx = Math.floor(sx / cell), cy = Math.floor(sy / cell);
  let best = null, bestD = Infinity;
  for (let i = -2; i <= 2; i++) {
    for (let j = -2; j <= 2; j++) {
      const bucket = screenIndex.get((cx + i) + "|" + (cy + j));
      if (!bucket) continue;
      for (const n of bucket) {
        const d = Math.hypot(n._sx - sx, n._sy - sy);
        const hitR = (n._sr || 6) + 6;
        if (d <= hitR && d < bestD) { bestD = d; best = n; }
      }
    }
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
  let best = null, bestD = 6 / Math.max(0.4, view.k);
  for (const e of edges) {
    if (edgeHidden(e)) continue;
    const a = byId.get(e.source), b = byId.get(e.target);
    if (!a || !b) continue;
    const ax = a._sx == null ? toScreen(a).x : a._sx;
    const ay = a._sy == null ? toScreen(a).y : a._sy;
    const bx = b._sx == null ? toScreen(b).x : b._sx;
    const by = b._sy == null ? toScreen(b).y : b._sy;
    const d = distToSeg(sx, sy, ax, ay, bx, by);
    if (d < bestD) { bestD = d; best = e; }
  }
  return best;
}

function getCanvasCoords(ev) {
  const rect = canvas.getBoundingClientRect();
  return { x: ev.clientX - rect.left, y: ev.clientY - rect.top };
}

// ---- hover tooltip ----

const tooltip = document.getElementById("graphTooltip");

function tooltipRows(node) {
  return [
    ["sam", node.sam_account_name || ""],
    ["domain", node.domain || ""],
    ["dn", node.distinguished_name || ""],
    ...Object.entries(node.props || {}),
  ].filter(([, v]) => v !== "" && v != null);
}

function positionTooltip(ev, node) {
  if (!tooltip) return;
  if (!node || !prefs.tooltips) { tooltip.hidden = true; return; }
  const rows = tooltipRows(node).slice(0, 6);
  tooltip.innerHTML = `<div class="tt-head"><span class="tt-dot" style="background:${COLORS[node.kind] || "#888"}"></span>`
    + `<span class="tt-title">${esc(nodeLabel(node))}</span>`
    + `<span class="tt-kind">${esc(node.kind)}</span></div>`
    + (rows.length ? `<dl class="tt-props">${rows.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(truncate(String(v), 48))}</dd>`).join("")}</dl>` : "");
  tooltip.hidden = false;
  const host = tooltip.offsetParent || document.body;
  const br = host.getBoundingClientRect();
  const tw = tooltip.offsetWidth, th = tooltip.offsetHeight;
  let x = ev.clientX - br.left + 16, y = ev.clientY - br.top + 16;
  if (x + tw > br.width - 8) x = ev.clientX - br.left - tw - 16;
  if (y + th > br.height - 8) y = ev.clientY - br.top - th - 16;
  tooltip.style.left = Math.max(4, x) + "px";
  tooltip.style.top = Math.max(4, y) + "px";
}

function hideTooltip() { if (tooltip) tooltip.hidden = true; }

// Pointer Events unify mouse, trackpad and touch, and pointer capture keeps a
// drag bound to the canvas even when the cursor leaves it.
if (canvas) {
  canvas.addEventListener("pointerdown", (ev) => {
    if (ev.pointerType === "mouse" && ev.button !== 0) return;
    if (canvas.setPointerCapture) { try { canvas.setPointerCapture(ev.pointerId); } catch (_) { /* ignore */ } }
    const c = getCanvasCoords(ev);
    const n = hitNode(c.x, c.y);
    drag.moved = false;
    drag.sx = c.x; drag.sy = c.y; drag.ox = view.x; drag.oy = view.y;
    if (n) {
      drag.node = n;
      drag.pin = !!n.fixed;
      n.fixed = true; // pin while dragging so physics cannot fight the cursor
      drag.panning = false;
      hideTooltip();
    } else {
      drag.node = null;
      drag.panning = true;
      canvas.classList.add("dragging");
    }
  });

  canvas.addEventListener("pointermove", (ev) => {
    const c = getCanvasCoords(ev);
    if (drag.node) {
      const wpt = toWorld(c.x, c.y);
      drag.node.x = wpt.x; drag.node.y = wpt.y;
      drag.node.vx = 0; drag.node.vy = 0;
      drag.moved = true;
      if (temp < 6) temp = 6; // let neighbours relax around the dragged node
      requestRender();
      return;
    }
    if (drag.panning) {
      view.x = drag.ox + (c.x - drag.sx);
      view.y = drag.oy + (c.y - drag.sy);
      drag.moved = true;
      requestRender();
      return;
    }
    const n = hitNode(c.x, c.y);
    const e = n ? null : hitEdge(c.x, c.y);
    if (n !== hoverNode || e !== hoverEdge) {
      hoverNode = n; hoverEdge = e;
      canvas.style.cursor = n || e ? "pointer" : "grab";
      requestRender();
    }
    positionTooltip(ev, n);
  });

  const endDrag = (ev) => {
    const c = getCanvasCoords(ev);
    canvas.classList.remove("dragging");
    if (drag.node) {
      // Keep the user's manual position: a dragged node stays pinned, so later
      // interactions never snap it back.
      drag.node.fixed = drag.moved ? true : drag.pin;
      if (!drag.moved) selectNode(drag.node);
      else { temp = Math.max(temp, 4); requestRender(); }
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
    if (canvas.releasePointerCapture && ev.pointerId != null) {
      try { canvas.releasePointerCapture(ev.pointerId); } catch (_) { /* ignore */ }
    }
  };
  canvas.addEventListener("pointerup", endDrag);
  canvas.addEventListener("pointercancel", endDrag);

  // Double-click a node to focus + expand its neighbourhood.
  canvas.addEventListener("dblclick", (ev) => {
    const c = getCanvasCoords(ev);
    const n = hitNode(c.x, c.y);
    if (n) { selectNode(n); focusNode(n); }
  });

  canvas.addEventListener("pointerleave", () => {
    if (!drag.node && !drag.panning) { hoverNode = null; hoverEdge = null; hideTooltip(); requestRender(); }
  });

  canvas.addEventListener("wheel", (ev) => {
    ev.preventDefault();
    const c = getCanvasCoords(ev);
    const factor = ev.deltaY < 0 ? 1.12 : 1 / 1.12;
    zoomBy(factor, c.x, c.y);
  }, { passive: false });
}

function clamp(v, lo, hi) { return Math.max(lo, Math.min(hi, v)); }

function fitView(padding = 60) {
  const vis = visibleNodes();
  if (vis.length === 0) return;
  let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
  for (const n of vis) {
    minX = Math.min(minX, n.x); minY = Math.min(minY, n.y);
    maxX = Math.max(maxX, n.x); maxY = Math.max(maxY, n.y);
  }
  if (!isFinite(minX)) return;
  const w = canvas.clientWidth, h = canvas.clientHeight;
  if (w === 0 || h === 0) return;
  const cx = (minX + maxX) / 2, cy = (minY + maxY) / 2;
  const spanX = Math.max(1, maxX - minX), spanY = Math.max(1, maxY - minY);
  const kx = (w - padding * 2) / spanX, ky = (h - padding * 2) / spanY;
  view.k = clamp(Math.min(kx, ky), 0.12, 2.5);
  view.x = w / 2 - cx * view.k;
  view.y = h / 2 - cy * view.k;
  requestRender();
}

function resetView() { fitView(); }

// Zoom about a screen anchor so the point under the cursor stays put.
function zoomBy(factor, cx, cy) {
  if (!canvas) return;
  const w = canvas.clientWidth, h = canvas.clientHeight;
  const px = cx == null ? w / 2 : cx, py = cy == null ? h / 2 : cy;
  const before = toWorld(px, py);
  view.k = clamp(view.k * factor, 0.08, 6);
  view.x = px - before.x * view.k;
  view.y = py - before.y * view.k;
  requestRender();
}

function centerOn(node, kTarget) {
  if (!canvas || !node) return;
  const w = canvas.clientWidth, h = canvas.clientHeight;
  if (kTarget) view.k = clamp(kTarget, 0.12, 6);
  view.x = w / 2 - node.x * view.k;
  view.y = h / 2 - node.y * view.k;
  requestRender();
}

function centerSelection() {
  if (selectedNode) centerOn(selectedNode);
  else if (selectedEdge) {
    const a = byId.get(selectedEdge.source), b = byId.get(selectedEdge.target);
    if (a && b) centerOn({ x: (a.x + b.x) / 2, y: (a.y + b.y) / 2 });
  }
}

// Select a node and bring it into view (used by search, graph search, Inspector).
function focusNode(node, kTarget) {
  if (!node) return;
  selectNode(node);
  centerOn(node, kTarget || Math.max(view.k, 1.1));
}

// Isolate the selected node + neighbours (hides everything else) or restore.
function toggleIsolate() {
  if (!selectedNode && !selectedEdge) { toast("Select a node or edge first", "warn"); return; }
  isolateMode = !isolateMode;
  applyFilters();
  if (isolateMode && selectedNode) centerSelection();
  syncGraphControls();
}

function syncGraphControls() {
  const iso = document.getElementById("isolateToggle");
  if (iso) { iso.classList.toggle("active", isolateMode); iso.setAttribute("aria-pressed", isolateMode ? "true" : "false"); }
  const he = document.getElementById("hideUnrelatedEdges");
  if (he) { he.classList.toggle("active", hideUnrelatedEdges); he.setAttribute("aria-pressed", hideUnrelatedEdges ? "true" : "false"); }
}

// Apply the toolbar node-kind filter, isolate mode and the header search.
function applyFilters() {
  const nodeKind = val("nodeKindFilter");
  const searchQ = val("search").toLowerCase();
  const anchor = isolateMode ? (selectedNode || hoverNode) : null;
  const keep = anchor ? neighborhood(anchor) : null;
  for (const n of nodes) {
    const kindHide = !!(nodeKind && n.kind !== nodeKind);
    const isolateHide = keep ? !keep.has(n.id) : false;
    n.hidden = kindHide || isolateHide;
    const hay = `${n.name || ""} ${n.sam_account_name || ""} ${n.id} ${n.kind || ""}`.toLowerCase();
    n.match = matchIds.has(n.id);
    n.dim = (searchQ !== "" && !hay.includes(searchQ)) || (keep ? !keep.has(n.id) : false);
  }
  const centerBtn = document.getElementById("centerSelection");
  if (centerBtn) centerBtn.disabled = !(selectedNode || selectedEdge);
  syncGraphControls();
  requestRender();
}

// ---------------------------------------------------------------------------
// Analysis state: starting node, target node, sessions, credentials, paths
// ---------------------------------------------------------------------------

// Stable key for an edge (nodes already use SIDs; kind keeps parallels distinct).
function edgeKey(e) { return `${e.source}|${e.kind}|${e.target}`; }

function startNode() { return startNodeId ? byId.get(startNodeId) || null : null; }
function targetNode() { return targetNodeId ? byId.get(targetNodeId) || null : null; }

function inPathNodes(id) { return !!(pathHighlight && pathHighlight.nodes.has(id)); }
function inPathEdges(e) { return !!(pathHighlight && pathHighlight.edges.has(edgeKey(e))); }

// Set the analysis origin. This is intentionally separate from `selectedNode`:
// the origin persists as the operator inspects other entities.
function setStartNode(id, opts = {}) {
  const n = id ? byId.get(id) || null : null;
  startNodeId = n ? n.id : null;
  if (n && opts.focus !== false) focusNode(n); // focusing also selects + centres
  updateStartUI();
  applyFilters();
  toast(n ? `Starting node: ${nodeLabel(n)}` : "Starting node cleared", "info");
  return n;
}

// Set the path destination. Also separate from the selection.
function setTargetNode(id) {
  const n = id ? byId.get(id) || null : null;
  targetNodeId = n ? n.id : null;
  updateStartUI();
  applyFilters();
  toast(n ? `Target: ${nodeLabel(n)}` : "Target cleared", "info");
  return n;
}

// Reflect start/target/selection state in the toolbar chips, buttons and hints.
function updateStartUI() {
  const s = startNode(), t = targetNode();
  const sChip = document.getElementById("startNodeChip");
  if (sChip) {
    if (s) {
      sChip.hidden = false;
      sChip.innerHTML = `<span class="chip-label">start</span> ${esc(truncate(nodeLabel(s), 22))} <span class="chip-kind">${esc(s.kind)}</span>`;
      sChip.title = `Starting node: ${nodeLabel(s)} (${s.kind})`;
    } else { sChip.hidden = true; sChip.innerHTML = ""; }
  }
  const tChip = document.getElementById("targetNodeChip");
  if (tChip) {
    if (t) {
      tChip.hidden = false;
      tChip.innerHTML = `<span class="chip-label">target</span> ${esc(truncate(nodeLabel(t), 22))} <span class="chip-kind">${esc(t.kind)}</span>`;
      tChip.title = `Target: ${nodeLabel(t)} (${t.kind})`;
    } else { tChip.hidden = true; tChip.innerHTML = ""; }
  }
  for (const id of ["setStartFromSelection", "setTargetFromSelection", "setStartFromNode", "setTargetFromNode"]) {
    const el = document.getElementById(id);
    if (el) el.disabled = !selectedNode;
  }
  const summary = document.getElementById("selectionSummary");
  if (summary) {
    if (selectedNode) summary.textContent = `Selected: ${truncate(nodeLabel(selectedNode), 24)} (${selectedNode.kind})`;
    else if (selectedEdge) summary.textContent = `Selected: ${truncate(selectedEdge.kind, 24)} relationship`;
    else summary.textContent = pathHighlight ? "Path highlighted" : "Nothing selected";
  }
  const hint = document.getElementById("startHint");
  if (hint) hint.textContent = s ? `Starting node: ${nodeLabel(s)} — use “⇄ Paths” to analyse from here.` : "Tip: choose a “Start from…” entity to anchor path analysis.";
  const clearBtn = document.getElementById("clearPathHighlight");
  if (clearBtn) clearBtn.hidden = !pathHighlight;
}

// Highlight a Path-Explorer result on the graph, then switch to the graph view.
function highlightPath(p) {
  if (!p) return;
  const nodeIds = new Set((p.nodes || []).map((n) => n.id));
  const edgeIds = new Set((p.relationships || []).map((e) => edgeKey(e)));
  pathHighlight = { nodes: nodeIds, edges: edgeIds, length: p.length };
  updateStartUI();
  setView("graph");
  applyFilters();
  // renderView fits the whole graph on a timer; fit the path just after.
  setTimeout(() => fitToNodes(nodeIds), 40);
  toast(`Path highlighted (${p.length} hop${p.length === 1 ? "" : "s"})`, "success");
}

function clearPathHighlight() {
  if (!pathHighlight) return;
  pathHighlight = null;
  updateStartUI();
  applyFilters();
  toast("Path highlight cleared", "info");
}

// Fit the viewport to a specific set of node ids (used for path highlight).
function fitToNodes(ids) {
  if (!canvas) return;
  const list = [];
  for (const id of ids) { const n = byId.get(id); if (n) list.push(n); }
  if (!list.length) return;
  let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
  for (const n of list) { minX = Math.min(minX, n.x); minY = Math.min(minY, n.y); maxX = Math.max(maxX, n.x); maxY = Math.max(maxY, n.y); }
  const w = canvas.clientWidth, h = canvas.clientHeight;
  if (!w || !h) return;
  const cx = (minX + maxX) / 2, cy = (minY + maxY) / 2;
  const spanX = Math.max(1, maxX - minX), spanY = Math.max(1, maxY - minY);
  view.k = clamp(Math.min((w - 160) / spanX, (h - 160) / spanY), 0.2, 2.2);
  view.x = w / 2 - cx * view.k;
  view.y = h / 2 - cy * view.k;
  requestRender();
}

// Observed sessions relevant to a node, split by the node's role (User vs host).
function sessionsFor(node) {
  const rec = adjacency.get(node.id) || { out: [], in: [], neighbors: [] };
  // HasSession is (User)-[:HasSession]->(Computer): outbound from user, inbound to host.
  return {
    onHosts: rec.out.filter((e) => e.kind === SESSION_EDGE),  // identity seen on these hosts
    here: rec.in.filter((e) => e.kind === SESSION_EDGE),      // hosts that observed these identities
  };
}

// Membership-ish edges in both directions, plus explicit delegated/admin rights.
function membershipsFor(node) {
  const rec = adjacency.get(node.id) || { out: [], in: [], neighbors: [] };
  const priv = new Set(["AdminTo", "AllowedToAct", "AllowedToDelegate", "CanRDP", "CanPSRemote", "ExecuteDCOM"]);
  return {
    memberOf: rec.out.filter((e) => e.kind === "MemberOf"),
    members: rec.in.filter((e) => e.kind === "MemberOf"),
    rights: rec.out.filter((e) => priv.has(e.kind)),
  };
}

// Credential *references* declared through the documented prop namespace (top of file).
function credentialEvidence(node) {
  return Object.entries(node.props || {})
    .filter(([k]) => k.startsWith(CRED_PREFIX))
    .map(([k, v]) => [k.slice(CRED_PREFIX.length), String(v)]);
}

// Mask a secret-ish value, keeping a short prefix/suffix so values can be told apart.
function maskSecret(v) {
  const s = String(v == null ? "" : v);
  if (s.length <= 4) return "••••";
  return `${s.slice(0, 2)}${"•".repeat(Math.min(24, s.length - 4))}${s.slice(-2)}`;
}

// Copy text to the clipboard without ever routing it through storage or logs.
function copyText(t, msg) {
  if (!t) return;
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(t).then(() => { if (msg) toast(msg, "success"); }).catch(() => toast("Copy failed", "warn"));
    return;
  }
  try {
    const ta = document.createElement("textarea");
    ta.value = t;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand("copy");
    ta.remove();
    if (msg) toast(msg, "success");
  } catch (_) { toast("Copy failed", "warn"); }
}

// Open Path Explorer with `node` pre-filled as the source (no duplicate engine).
function openPathsFrom(node) {
  if (!node) return;
  pathSrcSel = node.id;
  const src = document.getElementById("pathSrc");
  if (src) src.value = nodeLabel(node);
  setView("paths");
}

// Toolbar "⇄ Paths": use the starting node (or the selection) as the source.
function findPathsFromStart() {
  const s = startNode() || selectedNode;
  if (!s) { toast("Choose a starting node first", "warn"); return; }
  openPathsFrom(s);
  const note = document.getElementById("pathNote");
  if (note) note.textContent = `Source set to ${nodeLabel(s)} — choose a destination, then run the search.`;
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
  hoverEdge = null;
  show("panel-empty");
  const centerBtn = document.getElementById("centerSelection");
  if (centerBtn) centerBtn.disabled = true;
  if (isolateMode) applyFilters();
  updateStartUI();
  requestRender();
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
    ...Object.entries(n.props || {}).filter(([k]) => !k.startsWith(CRED_PREFIX)),
  ].filter(([, v]) => v !== "" && v !== undefined && v !== null);
  const propsEl = document.getElementById("node-props");
  if (propsEl) {
    propsEl.innerHTML = rows.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(String(v))}</dd>`).join("");
  }

  const rec = adjacency.get(n.id) || { out: [], in: [], neighbors: [] };
  const out = rec.out, inc = rec.in;
  const outEl = document.getElementById("node-out");
  const inEl = document.getElementById("node-in");
  if (outEl) outEl.innerHTML = edgeList(out, "target", "→");
  if (inEl) inEl.innerHTML = edgeList(inc, "source", "←");
  const outCount = document.getElementById("nodeOutCount");
  const inCount = document.getElementById("nodeInCount");
  if (outCount) outCount.textContent = out.length;
  if (inCount) inCount.textContent = inc.length;
  const connEl = document.getElementById("nodeConnected");
  if (connEl) connEl.textContent = rec.neighbors.length;

  renderNodeMemberships(n);
  renderNodeSessions(n);
  renderNodeCredentials(n);
  renderNodeProvenance(n);

  // Clicking a relationship row inspects that edge...
  for (const li of document.querySelectorAll("#panel-node li[data-src]")) {
    li.addEventListener("click", (ev) => {
      if (ev.target.closest("[data-node]")) return;
      const e = edges.find((x) => x.source === li.dataset.src && x.target === li.dataset.tgt && x.kind === li.dataset.kind);
      if (e) selectEdge(e);
    });
  }
  // ...clicking the connected entity selects + focuses that node in the graph.
  for (const btn of document.querySelectorAll("#panel-node [data-node]")) {
    btn.addEventListener("click", (ev) => {
      ev.stopPropagation();
      const tgt = byId.get(btn.dataset.node);
      if (tgt) focusNode(tgt);
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
  syncGraphControls();
  updateStartUI();
  requestRender();
}

// ---- Inspector section renderers (structure comes from real graph evidence) ----

function renderNodeMemberships(n) {
  const el = document.getElementById("node-memberships");
  if (!el) return;
  const m = membershipsFor(n);
  const parts = [];
  if (m.memberOf.length) parts.push(`<h4 class="rel-head">Member of</h4><ul class="edges" role="list">${edgeList(m.memberOf, "target", "→")}</ul>`);
  if (m.members.length) parts.push(`<h4 class="rel-head">Members</h4><ul class="edges" role="list">${edgeList(m.members, "source", "←")}</ul>`);
  if (m.rights.length) parts.push(`<h4 class="rel-head">Rights over</h4><ul class="edges" role="list">${edgeList(m.rights, "target", "→")}</ul>`);
  el.innerHTML = parts.length
    ? parts.join("")
    : '<p class="muted small">No membership or role relationships for this entity in the dataset.</p>';
}

function renderNodeSessions(n) {
  const el = document.getElementById("node-sessions");
  if (!el) return;
  const s = sessionsFor(n);
  const parts = [];
  if (s.onHosts.length) parts.push(`<h4 class="rel-head">Observed on hosts</h4><ul class="edges" role="list">${edgeList(s.onHosts, "target", "→")}</ul>`);
  if (s.here.length) parts.push(`<h4 class="rel-head">Identities observed here</h4><ul class="edges" role="list">${edgeList(s.here, "source", "←")}</ul>`);
  if (!parts.length) {
    el.innerHTML = '<p class="muted small">No session evidence for this entity in the current dataset.</p>' +
      '<p class="muted small">Sessions appear only when a collector observed them (e.g. <code>-c session</code> over SMB) or an imported dataset contained them. No session is inferred from unrelated edges.</p>';
    return;
  }
  el.innerHTML = parts.join("") +
    '<p class="muted small session-note">These are observations made at collection time. The dataset carries no per-session timestamp or validity flag, so no observed/stale status is asserted.</p>';
}

function renderNodeCredentials(n) {
  const el = document.getElementById("node-credentials");
  if (!el) return;
  const creds = credentialEvidence(n);
  if (!creds.length) {
    el.innerHTML = '<p class="muted small">No credential evidence in this dataset for this entity.</p>' +
      '<p class="muted small">OmenHound does not store secrets in the graph. If an importer supplies credential <em>references</em> under the ' +
      `<code>${esc(CRED_PREFIX)}</code> property namespace, they are shown here masked by default. Absence here is never proof of absence of credentials.</p>`;
    return;
  }
  const rows = creds.map(([k, v], i) =>
    `<dt>${esc(k)}</dt><dd><span class="secret" data-secret="${esc(v)}" data-i="${i}">${esc(maskSecret(v))}</span> <button type="button" class="link-node reveal-secret" data-i="${i}">reveal</button></dd>`
  ).join("");
  el.innerHTML = `<dl class="cred-dl">${rows}</dl>
    <p class="muted small">Credential references only — never raw secrets. Values are masked by default, are held in the DOM only while this panel is open, and are never written to browser storage, the URL or logs. A reference is not evidence that authentication would succeed.</p>`;
  el.querySelectorAll(".reveal-secret").forEach((b) => {
    b.addEventListener("click", () => {
      const span = el.querySelector(`.secret[data-i="${b.dataset.i}"]`);
      if (!span) return;
      const shown = span.dataset.shown === "1";
      span.textContent = shown ? maskSecret(span.dataset.secret) : span.dataset.secret;
      span.dataset.shown = shown ? "0" : "1";
      b.textContent = shown ? "reveal" : "hide";
    });
  });
}

function renderNodeProvenance(n) {
  const el = document.getElementById("node-provenance");
  if (!el) return;
  const rows = [["node_id", n.id], ["kind", n.kind]];
  if (n.domain) rows.push(["domain", n.domain]);
  if (n.distinguished_name) rows.push(["dn", n.distinguished_name]);
  if (statsCache) rows.push(["graph_total", `${statsCache.nodes} nodes / ${statsCache.edges} edges`]);
  const dl = rows.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(String(v))}</dd>`).join("");
  el.innerHTML = `<dl class="prov-dl">${dl}</dl>
    <p class="muted small">The read API exposes graph structure only; collection-run metadata (collector name, run timestamps) is not persisted, so none is fabricated here. Entities are keyed by their stable identifier — the AD SID, or objectGUID when no SID exists.</p>`;
}


function edgeList(list, other, dir) {
  if (!list.length) return "<li class='muted'>none</li>";
  return list.map((e) => {
    const o = byId.get(e[other]);
    const name = o ? nodeLabel(o) : e[other];
    const link = `<button type="button" class="link-node" data-node="${esc(e[other])}" title="Select this entity">${esc(truncate(name, 26))}</button>`;
    return `<li data-src="${esc(e.source)}" data-tgt="${esc(e.target)}" data-kind="${esc(e.kind)}" title="Click to inspect this relationship"><span class="k">${esc(e.kind)}</span> <span class="target">${dir} ${link}</span></li>`;
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

  // Session relationships get an explicit evidence note, never invented metadata.
  const sessionNote = document.getElementById("edge-session-note");
  if (sessionNote) {
    if (e.kind === SESSION_EDGE) {
      sessionNote.hidden = false;
      sessionNote.innerHTML = `<strong>Observed session.</strong> The collector saw <em>${esc(a ? nodeLabel(a) : e.source)}</em> on <em>${esc(b ? nodeLabel(b) : e.target)}</em>. ` +
        `The dataset records no per-session timestamp or validity, so no observed/stale/expired state is asserted. A session is not proof that the identity can authenticate with every credential associated with it.`;
    } else {
      sessionNote.hidden = true;
      sessionNote.textContent = "";
    }
  }

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
  if (propsEl) {
    const meta = [
      ["type", e.kind],
      ["source", a ? nodeLabel(a) : e.source],
      ["target", b ? nodeLabel(b) : e.target],
      ["direction", `${a ? nodeLabel(a) : e.source} → ${b ? nodeLabel(b) : e.target}`],
    ].filter(([, v]) => v !== "" && v != null);
    propsEl.innerHTML = meta.concat(Object.entries(e.props || {}))
      .map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(String(v))}</dd>`).join("");
  }

  const centerBtn = document.getElementById("centerSelection");
  if (centerBtn) centerBtn.disabled = false;
  syncGraphControls();
  updateStartUI();
  requestRender();

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
    refreshDataMgmt();
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
    if (n) { selectNode(n); setTimeout(() => { centerSelection(); }, 60); }
  } else if (ctx.type === "edge") {
    const e = ctx.edge;
    selectEdge(e);
    setTimeout(() => { centerSelection(); }, 60);
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

// Reflect the current graph size in the Ingestion "Delete data" block.
async function refreshDataMgmt() {
  const el = document.getElementById("clearStatus");
  const btn = document.getElementById("clearGraph");
  if (!el && !btn) return;
  try {
    const s = await apiGet("/api/v1/stats");
    const nodes = Number(s.nodes) || 0, edges = Number(s.edges) || 0;
    if (el) { el.textContent = `Current graph: ${nodes} nodes · ${edges} edges`; el.className = "muted"; }
    if (btn) btn.disabled = nodes === 0 && edges === 0;
  } catch (_) {
    if (el) { el.textContent = "Current graph: unavailable"; el.className = "muted"; }
    if (btn) btn.disabled = false;
  }
}

// Drop selection, start/target anchors and path highlight after the graph is
// replaced or cleared, so no control keeps pointing at a deleted entity.
function resetGraphUI() {
  startNodeId = null;
  targetNodeId = null;
  pathHighlight = null;
  isolateMode = false;
  clearSelection();
  updateStartUI();
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
      const replaceEl = document.getElementById("ingestReplace");
      const file = fileEl && fileEl.files ? fileEl.files[0] : null;
      const token = tokenEl ? tokenEl.value.trim() : "";
      const replace = !!(replaceEl && replaceEl.checked);
      if (!file || !token) {
        if (statusEl) { statusEl.textContent = "Select a Graph JSON file and provide an operator token."; statusEl.className = "warn"; }
        return;
      }
      if (replace && !window.confirm("Replace the existing graph? All current data will be deleted before ingesting this file.")) {
        if (statusEl) { statusEl.textContent = "Cancelled — nothing was changed."; statusEl.className = "muted"; }
        return;
      }
      if (statusEl) { statusEl.textContent = replace ? "Replacing graph…" : "Uploading…"; statusEl.className = "muted"; }
      try {
        const text = await file.text();
        const url = replace ? "/api/v1/ingest?mode=replace" : "/api/v1/ingest";
        const res = await fetch(url, {
          method: "POST",
          headers: { "Content-Type": "application/json", Authorization: "Bearer " + token },
          body: text,
        });
        const r = await res.json().catch(() => ({}));
        if (!res.ok) throw new Error(r.error || res.statusText);
        if (statusEl) { statusEl.textContent = `OK: ${r.nodes} nodes, ${r.edges} edges ${replace ? "replaced" : "ingested"}`; statusEl.className = "success"; }
        operatorToken = token;
        setLock(true);
        toast(`${replace ? "Replaced with" : "Ingested"} ${r.nodes} nodes, ${r.edges} edges`, "success");
        if (replace) { resetGraphUI(); await reloadGraph(); }
        else if (prefs.autoRefresh) await refresh();
        await refreshDataMgmt();
      } catch (err) {
        if (statusEl) { statusEl.textContent = "Error: " + err.message; statusEl.className = "warn"; }
        toast("Ingest failed: " + err.message, "error");
      }
    });
  }

  const clearBtn = document.getElementById("clearGraph");
  if (clearBtn) {
    clearBtn.addEventListener("click", async () => {
      const tokenEl = document.getElementById("ingestToken");
      const statusEl = document.getElementById("clearStatus");
      let token = tokenEl ? tokenEl.value.trim() : "";
      if (!token && operatorToken) token = operatorToken;
      if (!token) {
        if (statusEl) { statusEl.textContent = "Enter an operator token above, then try again."; statusEl.className = "warn"; }
        toast("Operator token required to delete data", "warn");
        return;
      }
      const stats = await apiGet("/api/v1/stats").catch(() => null);
      const summary = stats ? `${Number(stats.nodes) || 0} nodes and ${Number(stats.edges) || 0} edges` : "all graph data";
      if (!window.confirm(`Delete ${summary}? This cannot be undone.`)) return;
      if (statusEl) { statusEl.textContent = "Deleting…"; statusEl.className = "muted"; }
      try {
        const res = await fetch("/api/v1/graph?confirm=true", {
          method: "DELETE",
          headers: { Authorization: "Bearer " + token },
        });
        const r = await res.json().catch(() => ({}));
        if (!res.ok) throw new Error(r.error || res.statusText);
        operatorToken = token;
        setLock(true);
        resetGraphUI();
        await reloadGraph();
        await refreshDataMgmt();
        toast("All graph data deleted", "success");
      } catch (err) {
        if (statusEl) { statusEl.textContent = "Error: " + err.message; statusEl.className = "warn"; }
        toast("Delete failed: " + err.message, "error");
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
          ? items.map((n) => `<div class="suggest-item" data-id="${esc(n.id)}" data-label="${esc(nodeLabel(n))}" role="option">${esc(nodeLabel(n))} <span class="kind">${esc(n.kind)}</span></div>`).join("")
          : '<div class="suggest-item muted">no matches</div>';
        res.hidden = false;
        res.querySelectorAll(".suggest-item[data-id]").forEach((el) => {
          el.addEventListener("click", () => {
            setter(el.dataset.id);
            input.value = el.dataset.label || el.textContent.trim();
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
            <div class="path-footer">
              <button type="button" class="show-path-btn chip-btn" data-path="${i}">⌖ Show on graph</button>
              <span class="muted small">Edges and direction are dataset evidence; a path is not asserted to be exploitable.</span>
            </div>
          </div>`;
        }).join("");
        // Highlight any path directly on the graph canvas.
        results.querySelectorAll(".show-path-btn").forEach((b) => {
          b.addEventListener("click", () => {
            const p = paths[Number(b.dataset.path)];
            if (p) highlightPath(p);
          });
        });
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
    ["settingArrows", "arrows"],
    ["settingTooltips", "tooltips"],
    ["settingPhysics", "physics"],
    ["settingReduceMotion", "reduceMotion"],
    ["settingAutoRefresh", "autoRefresh"],
    ["settingPreserveSelection", "preserveSelection"],
  ];
  pairs.forEach(([id, key]) => {
    const el = document.getElementById(id);
    if (el) el.addEventListener("change", () => { prefs[key] = el.checked; savePrefs(); requestRender(); });
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
  const arrowToggle = document.getElementById("showArrows");
  if (arrowToggle) arrowToggle.addEventListener("change", () => { prefs.arrows = arrowToggle.checked; savePrefs(); renderLegend(); requestRender(); });
}

// Find a node by name / identifier from the graph toolbar. Matches are
// highlighted and the first match is focused automatically.
function wireGraphSearch() {
  const el = document.getElementById("graphSearch");
  if (!el) return;
  let t = null;
  const run = (focus) => {
    const q = el.value.trim().toLowerCase();
    matchIds = new Set();
    if (!q) { applyFilters(); return; }
    let first = null;
    for (const n of nodes) {
      const hay = `${n.name || ""} ${n.sam_account_name || ""} ${n.id} ${n.kind || ""}`.toLowerCase();
      if (hay.includes(q)) { matchIds.add(n.id); if (!first) first = n; }
    }
    applyFilters();
    if (focus && first) focusNode(first, Math.max(view.k, 1.15));
  };
  el.addEventListener("input", () => { clearTimeout(t); t = setTimeout(() => run(false), 200); });
  el.addEventListener("keydown", (ev) => {
    if (ev.key === "Enter") { ev.preventDefault(); run(true); }
    if (ev.key === "Escape") { el.value = ""; matchIds = new Set(); applyFilters(); }
  });
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
        await reloadGraph();
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
  if (fitViewBtn) fitViewBtn.addEventListener("click", () => fitView());
  const resetViewBtn = document.getElementById("resetView");
  if (resetViewBtn) resetViewBtn.addEventListener("click", resetView);
  const centerSelectionBtn = document.getElementById("centerSelection");
  if (centerSelectionBtn) centerSelectionBtn.addEventListener("click", centerSelection);

  const zoomInBtn = document.getElementById("zoomIn");
  if (zoomInBtn) zoomInBtn.addEventListener("click", () => zoomBy(1.25));
  const zoomOutBtn = document.getElementById("zoomOut");
  if (zoomOutBtn) zoomOutBtn.addEventListener("click", () => zoomBy(1 / 1.25));
  const restartBtn = document.getElementById("restartLayout");
  if (restartBtn) restartBtn.addEventListener("click", () => { restartLayout(); toast("Layout restarted", "info"); });
  const isolateBtn = document.getElementById("isolateToggle");
  if (isolateBtn) isolateBtn.addEventListener("click", toggleIsolate);
  const hideEdgesBtn = document.getElementById("hideUnrelatedEdges");
  if (hideEdgesBtn) hideEdgesBtn.addEventListener("click", () => {
    hideUnrelatedEdges = !hideUnrelatedEdges;
    syncGraphControls();
    requestRender();
  });
  const clearSelBtn = document.getElementById("clearSelectionBtn");
  if (clearSelBtn) clearSelBtn.addEventListener("click", clearSelection);

  const reloadEl = document.getElementById("reload");
  if (reloadEl) reloadEl.addEventListener("click", () => reloadGraph().then(() => toast("Graph reloaded", "success")).catch((e) => toast("Reload failed: " + e.message, "error")));

  const nodeKindFilter = document.getElementById("nodeKindFilter");
  if (nodeKindFilter) nodeKindFilter.addEventListener("change", () => { applyFilters(); fitView(); });
  const edgeKindFilter = document.getElementById("edgeKindFilter");
  if (edgeKindFilter) edgeKindFilter.addEventListener("change", () => { applyFilters(); });

  // ---- Starting node picker (search / select / focus) ----
  wirePathSuggest("startNodeSearch", "startNodeRes", (id) => setStartNode(id));

  // ---- Selection -> start / target ----
  const setStartBtn = document.getElementById("setStartFromSelection");
  if (setStartBtn) setStartBtn.addEventListener("click", () => { if (selectedNode) setStartNode(selectedNode.id); });
  const setTargetBtn = document.getElementById("setTargetFromSelection");
  if (setTargetBtn) setTargetBtn.addEventListener("click", () => { if (selectedNode) setTargetNode(selectedNode.id); });
  const clearPathBtn = document.getElementById("clearPathHighlight");
  if (clearPathBtn) clearPathBtn.addEventListener("click", clearPathHighlight);

  // ---- Sessions-only filter ----
  const sessionsBtn = document.getElementById("sessionsOnly");
  if (sessionsBtn) {
    sessionsBtn.addEventListener("click", () => {
      sessionsOnly = !sessionsOnly;
      sessionsBtn.classList.toggle("active", sessionsOnly);
      sessionsBtn.setAttribute("aria-pressed", sessionsOnly ? "true" : "false");
      applyFilters();
    });
  }

  // ---- Analysis: open Path Explorer from the starting node ----
  const findPathsBtn = document.getElementById("findPathsFromGraph");
  if (findPathsBtn) findPathsBtn.addEventListener("click", findPathsFromStart);

  // ---- Inspector: collapse / hide / reopen ----
  const panelCollapse = document.getElementById("panelCollapse");
  if (panelCollapse) {
    panelCollapse.addEventListener("click", () => {
      const panelEl = document.getElementById("panel");
      if (!panelEl) return;
      const collapsed = panelEl.classList.toggle("collapsed");
      panelCollapse.classList.toggle("active", collapsed);
      panelCollapse.setAttribute("aria-pressed", collapsed ? "true" : "false");
      panelCollapse.textContent = collapsed ? "⟨" : "⟩";
      panelCollapse.title = collapsed ? "Expand panel" : "Collapse panel";
      setTimeout(resize, 200);
    });
  }
  const toggleInspector = document.getElementById("toggleInspector");
  if (toggleInspector) {
    toggleInspector.addEventListener("click", () => {
      const panelEl = document.getElementById("panel");
      if (!panelEl) return;
      const hidden = panelEl.classList.toggle("hidden");
      toggleInspector.classList.toggle("active", !hidden);
      toggleInspector.setAttribute("aria-pressed", hidden ? "false" : "true");
      setTimeout(resize, 200);
    });
  }

  // ---- Inspector node actions ----
  const nodeActions = {
    setStartFromNode: () => { if (selectedNode) setStartNode(selectedNode.id); },
    setTargetFromNode: () => { if (selectedNode) setTargetNode(selectedNode.id); },
    focusNodeBtn: () => { if (selectedNode) focusNode(selectedNode); },
    findPathsFromNode: () => { if (selectedNode) openPathsFrom(selectedNode); },
    copyNodeId: () => { if (selectedNode) copyText(selectedNode.id, "Identifier copied"); },
  };
  for (const [id, fn] of Object.entries(nodeActions)) {
    const el = document.getElementById(id);
    if (el) el.addEventListener("click", fn);
  }

  // ---- Inspector relationship actions ----
  const edgeActions = {
    focusEdgeSource: () => { const n = selectedEdge && byId.get(selectedEdge.source); if (n) focusNode(n); },
    focusEdgeTarget: () => { const n = selectedEdge && byId.get(selectedEdge.target); if (n) focusNode(n); },
    setStartFromEdge: () => { if (selectedEdge) setStartNode(selectedEdge.source); },
    setTargetFromEdge: () => { if (selectedEdge) setTargetNode(selectedEdge.target); },
    filterEdgeKind: () => {
      if (!selectedEdge) return;
      const sel = document.getElementById("edgeKindFilter");
      if (sel) { sel.value = selectedEdge.kind; applyFilters(); }
    },
  };
  for (const [id, fn] of Object.entries(edgeActions)) {
    const el = document.getElementById(id);
    if (el) el.addEventListener("click", fn);
  }

  // ---- Inspector close (keeps the graph selection) vs clear selection ----
  const panelClose = document.getElementById("panelClose");
  if (panelClose && !panelClose.dataset.bound) {
    panelClose.dataset.bound = "1";
    panelClose.addEventListener("click", () => {
      const panelEl = document.getElementById("panel");
      if (panelEl) panelEl.classList.add("hidden");
      const ti = document.getElementById("toggleInspector");
      if (ti) { ti.classList.remove("active"); ti.setAttribute("aria-pressed", "false"); }
      setTimeout(resize, 200);
    });
  }
  // Note: the old behaviour of #panelClose was clearSelection; that was removed
  // so closing the panel no longer destroys the selection. Esc still clears it.

  const showArrows = document.getElementById("showArrows");
  if (showArrows) showArrows.addEventListener("change", () => { prefs.arrows = showArrows.checked; savePrefs(); renderLegend(); requestRender(); });

  wireGraphSearch();

  const openInGraph = document.getElementById("openInGraph");
  if (openInGraph) openInGraph.addEventListener("click", () => { if (selectedNode) centerSelection(); });

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

// Reload the graph and recompute the layout, then re-render the current view.
async function reloadGraph() {
  await refresh();
  settleLayout();
  renderView(parseHash());
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
    renderView(startView);
  }).catch(() => {});
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
    case "/":
      e.preventDefault();
      const gs = document.getElementById("graphSearch");
      if (gs) gs.focus();
      break;
    case "Escape": {
      if (gate && !gate.hidden) closeGate();
      else {
        const modal = document.getElementById("objectModal");
        if (modal && !modal.hidden) closeObjectModal();
        else { clearSelection(); clearPathHighlight(); }
      }
      break;
    }
  }
});

try { attachNav(); } catch (_) {}
if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", init);
} else {
  init();
}

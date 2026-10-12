"use strict";

// OmenHound UI — dependency-free force-directed graph on a canvas.
// No CDN: works fully offline and ships inside the Go binary.

const COLORS = {
  User: "#00d4ff",
  Group: "#ff6b35",
  Computer: "#00ff88",
  Domain: "#b873ff",
  GPO: "#ff3d7f",
  OU: "#ffd600",
  Container: "#4ecdc4",
  Trust: "#ff8c42",
};

const canvas = document.getElementById("graph");
const ctx = canvas.getContext("2d");

let nodes = [];
let edges = [];
let byId = new Map();
let alpha = 1;
let selectedNode = null;
let selectedEdge = null;

// view transform: screen = world * k + (x, y)
let view = { x: 0, y: 0, k: 1 };

const drag = { node: null, panning: false, moved: false, sx: 0, sy: 0, ox: 0, oy: 0 };

function resize() {
  const parent = canvas.parentElement;
  if (!parent) return;
  const r = parent.getBoundingClientRect();
  const dpr = window.devicePixelRatio || 1;
  canvas.width = r.width * dpr;
  canvas.height = r.height * dpr;
  canvas.style.width = r.width + "px";
  canvas.style.height = r.height + "px";
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
}
window.addEventListener("resize", resize);

function toScreen(p) {
  return { x: p.x * view.k + view.x, y: p.y * view.k + view.y };
}
function toWorld(sx, sy) {
  return { x: (sx - view.x) / view.k, y: (sy - view.y) / view.k };
}

async function loadGraph() {
  try {
    const res = await fetch("/api/v1/graph");
    const g = await res.json();
    nodes = (g.nodes || []).map((n, i) => ({
      ...n,
      x: Math.cos(i) * 120 + (Math.random() - 0.5) * 60,
      y: Math.sin(i) * 120 + (Math.random() - 0.5) * 60,
      vx: 0,
      vy: 0,
    }));
    edges = (g.edges || []).map((e) => ({
      ...e,
      source: String(e.source),
      target: String(e.target),
    }));
    byId = new Map(nodes.map((n) => [n.id, n]));
    edges = edges.filter((e) => byId.has(e.source) && byId.has(e.target));
    alpha = 1;
    const statsEl = document.getElementById("stats");
    if (statsEl) statsEl.textContent = `${nodes.length} nodes · ${edges.length} edges`;
    renderLegend();
    populateFilters();
  } catch (e) {
    const statsEl = document.getElementById("stats");
    if (statsEl) statsEl.textContent = "Failed to load graph";
  }
}

function renderLegend() {
  const kinds = [...new Set(nodes.map((n) => n.kind))].sort();
  const legendEl = document.getElementById("legend");
  if (legendEl) {
    legendEl.innerHTML = kinds.map((k) => `<span><i style="background:${COLORS[k] || "#888"}"></i>${k}</span>`).join("");
  }
}

function populateFilters() {
  const nodeKindFilter = document.getElementById("nodeKindFilter");
  const edgeKindFilter = document.getElementById("edgeKindFilter");
  if (nodeKindFilter) {
    const kinds = [...new Set(nodes.map((n) => n.kind))].sort();
    nodeKindFilter.innerHTML = '<option value="">All Types</option>' + kinds.map(k => `<option value="${esc(k)}">${k}</option>`).join("");
  }
  if (edgeKindFilter) {
    const kinds = [...new Set(edges.map((e) => e.kind))].sort();
    edgeKindFilter.innerHTML = '<option value="">All Relationships</option>' + kinds.map(k => `<option value="${esc(k)}">${k}</option>`).join("");
  }
}

function step() {
  // repulsion
  for (let i = 0; i < nodes.length; i++) {
    for (let j = i + 1; j < nodes.length; j++) {
      const a = nodes[i], b = nodes[j];
      let dx = a.x - b.x, dy = a.y - b.y;
      let d2 = dx * dx + dy * dy || 0.01;
      const d = Math.sqrt(d2);
      const f = 1800 / d2;
      const fx = (dx / d) * f, fy = (dy / d) * f;
      a.vx += fx; a.vy += fy; b.vx -= fx; b.vy -= fy;
    }
  }
  // springs
  for (const e of edges) {
    const a = byId.get(e.source), b = byId.get(e.target);
    if (!a || !b) continue;
    let dx = b.x - a.x, dy = b.y - a.y;
    const d = Math.sqrt(dx * dx + dy * dy) || 0.01;
    const f = (d - 110) * 0.02;
    const fx = (dx / d) * f, fy = (dy / d) * f;
    a.vx += fx; a.vy += fy; b.vx -= fx; b.vy -= fy;
  }
  // gravity + integrate
  for (const n of nodes) {
    n.vx += -n.x * 0.002;
    n.vy += -n.y * 0.002;
    n.x += n.vx * alpha;
    n.y += n.vy * alpha;
    n.vx *= 0.85;
    n.vy *= 0.85;
  }
  alpha *= 0.99;
}

function draw() {
  if (!canvas.parentElement) return;
  const w = canvas.clientWidth, h = canvas.clientHeight;
  if (w === 0 || h === 0) return;
  ctx.clearRect(0, 0, w, h);

  // edges
  ctx.lineWidth = 1.2;
  for (const e of edges) {
    const a = toScreen(byId.get(e.source));
    const b = toScreen(byId.get(e.target));
    const sel = selectedEdge && selectedEdge.source === e.source && selectedEdge.target === e.target && selectedEdge.kind === e.kind;
    ctx.strokeStyle = sel ? "#00ff88" : "rgba(140,152,178,0.35)";
    ctx.beginPath();
    ctx.moveTo(a.x, a.y);
    ctx.lineTo(b.x, b.y);
    ctx.stroke();
  }
  // edge labels (when zoomed in or selected)
  if (view.k > 0.8) {
    ctx.save();
    ctx.font = "10px ui-sans-serif,system-ui,sans-serif";
    ctx.fillStyle = "rgba(230,233,240,0.8)";
    ctx.textAlign = "center";
    ctx.textBaseline = "middle";
    for (const e of edges) {
      const a = toScreen(byId.get(e.source));
      const b = toScreen(byId.get(e.target));
      const mx = (a.x + b.x) / 2;
      const my = (a.y + b.y) / 2;
      const label = e.kind;
      ctx.fillText(label, mx, my);
    }
    ctx.restore();
  }

  // nodes
  for (const n of nodes) {
    const p = toScreen(n);
    const r = (n.kind === "Domain" ? 12 : 8) * Math.max(0.6, Math.min(1.6, view.k));
    ctx.globalAlpha = n.dim ? 0.15 : 1;
    ctx.beginPath();
    ctx.arc(p.x, p.y, r, 0, Math.PI * 2);
    ctx.fillStyle = COLORS[n.kind] || "#888";
    ctx.fill();
    if (selectedNode === n) {
      ctx.lineWidth = 2.5;
      ctx.strokeStyle = "#fff";
      ctx.stroke();
    }
    if (view.k > 0.7 && !n.dim) {
      ctx.fillStyle = "rgba(230,233,240,0.85)";
      ctx.font = "11px ui-sans-serif,system-ui,sans-serif";
      ctx.fillText(n.name || n.sam_account_name || n.id, p.x + r + 3, p.y + 3);
    }
    ctx.globalAlpha = 1;
  }
}

function loop() {
  if (alpha > 0.001) {
    for (let i = 0; i < 3; i++) step();
  }
  draw();
  requestAnimationFrame(loop);
}

// Run initial layout off-screen (fast-forward physics) before first render
function settleLayout() {
  // Run many iterations quickly without rendering
  for (let i = 0; i < 200; i++) {
    step();
    if (alpha <= 0.01) break;
  }
  // Reset alpha for smooth interaction after initial layout
  alpha = 0.1;
}

// ---- interaction ----

function hitNode(sx, sy) {
  // Hit radius scales inversely with zoom for consistent click targets
  const baseRadius = 14;
  const scaledRadius = baseRadius / Math.max(0.5, view.k);
  let best = null, bestD = scaledRadius;
  for (const n of nodes) {
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
  // Hit distance scales inversely with zoom
  const baseDist = 6;
  const scaledDist = baseDist / Math.max(0.5, view.k);
  let best = null, bestD = scaledDist;
  for (const e of edges) {
    const a = toScreen(byId.get(e.source));
    const b = toScreen(byId.get(e.target));
    const d = distToSeg(sx, sy, a.x, a.y, b.x, b.y);
    if (d < bestD) { bestD = d; best = e; }
  }
  return best;
}

// Get canvas-relative coordinates accounting for borders
function getCanvasCoords(ev) {
  const rect = canvas.getBoundingClientRect();
  return {
    x: ev.clientX - rect.left,
    y: ev.clientY - rect.top
  };
}

canvas.addEventListener("mousedown", (ev) => {
  const coords = getCanvasCoords(ev);
  const sx = coords.x, sy = coords.y;
  const n = hitNode(sx, sy);
  drag.moved = false;
  drag.sx = sx; drag.sy = sy; drag.ox = view.x; drag.oy = view.y;
  if (n) {
    drag.node = n;
    n.fixed = true;
  } else {
    drag.panning = true;
    canvas.classList.add("dragging");
  }
});

canvas.addEventListener("mousemove", (ev) => {
  const coords = getCanvasCoords(ev);
  const sx = coords.x, sy = coords.y;
  if (drag.node) {
    const w = toWorld(sx, sy);
    drag.node.x = w.x; drag.node.y = w.y;
    drag.node.vx = 0; drag.node.vy = 0;
    drag.moved = true;
    alpha = Math.max(alpha, 0.15);
  } else if (drag.panning) {
    view.x = drag.ox + (sx - drag.sx);
    view.y = drag.oy + (sy - drag.sy);
    drag.moved = true;
  }
});

canvas.addEventListener("mouseup", (ev) => {
  const coords = getCanvasCoords(ev);
  const sx = coords.x, sy = coords.y;
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

canvas.addEventListener("wheel", (ev) => {
  ev.preventDefault();
  const coords = getCanvasCoords(ev);
  const sx = coords.x, sy = coords.y;
  const before = toWorld(sx, sy);
  const factor = ev.deltaY < 0 ? 1.12 : 1 / 1.12;
  view.k = Math.max(0.15, Math.min(4, view.k * factor));
  const after = toWorld(sx, sy);
  view.x += (after.x - before.x) * view.k;
  view.y += (after.y - before.y) * view.k;
}, { passive: false });

// Touch support for mobile
canvas.addEventListener("touchstart", (ev) => {
  if (ev.touches.length === 1) {
    const touch = ev.touches[0];
    const coords = getCanvasCoords(touch);
    const sx = coords.x, sy = coords.y;
    const n = hitNode(sx, sy);
    drag.moved = false;
    drag.sx = sx; drag.sy = sy; drag.ox = view.x; drag.oy = view.y;
    if (n) {
      drag.node = n;
      n.fixed = true;
    } else {
      drag.panning = true;
      canvas.classList.add("dragging");
    }
    ev.preventDefault();
  }
}, { passive: false });

canvas.addEventListener("touchmove", (ev) => {
  if (ev.touches.length === 1) {
    const touch = ev.touches[0];
    const coords = getCanvasCoords(touch);
    const sx = coords.x, sy = coords.y;
    if (drag.node) {
      const w = toWorld(sx, sy);
      drag.node.x = w.x; drag.node.y = w.y;
      drag.node.vx = 0; drag.node.vy = 0;
      drag.moved = true;
      alpha = Math.max(alpha, 0.15);
    } else if (drag.panning) {
      view.x = drag.ox + (sx - drag.sx);
      view.y = drag.oy + (sy - drag.sy);
      drag.moved = true;
    }
    ev.preventDefault();
  }
}, { passive: false });

canvas.addEventListener("touchend", (ev) => {
  // Use last touch position or center of canvas
  let sx = drag.sx, sy = drag.sy;
  if (ev.changedTouches.length === 1) {
    const coords = getCanvasCoords(ev.changedTouches[0]);
    sx = coords.x; sy = coords.y;
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

// ---- panels ----

function show(id) {
  for (const s of ["panel-empty", "panel-node", "panel-edge"]) {
    const el = document.getElementById(s);
    if (el) el.hidden = s !== id;
  }
}

function selectNode(n) {
  selectedNode = n;
  selectedEdge = null;
  show("panel-node");
  const titleEl = document.getElementById("node-title");
  if (titleEl) titleEl.textContent = n.name || n.sam_account_name || n.id;
  const rows = [
    ["kind", n.kind],
    ["sid", n.id],
    ["sam", n.sam_account_name || ""],
    ["domain", n.domain || ""],
    ["dn", n.distinguished_name || ""],
    ...Object.entries(n.props || {}),
  ].filter(([, v]) => v !== "" && v !== undefined);
  const propsEl = document.getElementById("node-props");
  if (propsEl) {
    propsEl.innerHTML = rows
      .map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(String(v))}</dd>`)
      .join("");
  }

  const out = edges.filter((e) => e.source === n.id);
  const inc = edges.filter((e) => e.target === n.id);
  const outEl = document.getElementById("node-out");
  const inEl = document.getElementById("node-in");
  if (outEl) outEl.innerHTML = edgeList(out, "target");
  if (inEl) inEl.innerHTML = edgeList(inc, "source");
  const openBtn = document.getElementById("openInGraph");
  if (openBtn) openBtn.disabled = true; // already in graph

  // Update counts
  const outCount = document.getElementById("nodeOutCount");
  const inCount = document.getElementById("nodeInCount");
  if (outCount) outCount.textContent = out.length;
  if (inCount) inCount.textContent = inc.length;

  // Re-attach click handlers to edge list items
  for (const li of document.querySelectorAll("#node-out li,#node-in li")) {
    li.onclick = () => {
      const e = edges.find((x) => x.source === li.dataset.src && x.target === li.dataset.tgt && x.kind === li.dataset.kind);
      if (e) selectEdge(e);
    };
  }
}

function edgeList(list, other) {
  return list
    .map((e) => {
      const o = byId.get(e[other]);
      const name = o ? o.name || o.sam_account_name || o.id : e[other];
      return `<li data-src="${esc(e.source)}" data-tgt="${esc(e.target)}" data-kind="${esc(e.kind)}"><span class="k">${esc(e.kind)}</span> → ${esc(name)}</li>`;
    })
    .join("") || "<li class='muted'>none</li>";
}

async function selectEdge(e) {
  selectedEdge = e;
  selectedNode = null;
  show("panel-edge");
  const a = byId.get(e.source), b = byId.get(e.target);
  const titleEl = document.getElementById("edge-title");
  const summaryEl = document.getElementById("edge-summary");
  if (titleEl) titleEl.textContent = `${e.kind}`;
  if (summaryEl) summaryEl.textContent = `${a ? a.name || a.id : e.source} → ${b ? b.name || b.id : e.target}`;
  const cmdEl = document.getElementById("edge-command");
  const opsecEl = document.getElementById("edge-opsec");
  const eventsEl = document.getElementById("edge-events");
  const warningsEl = document.getElementById("edge-warnings");
  const altsWrap = document.getElementById("edge-alts-wrap");
  const altsEl = document.getElementById("edge-alts");
  if (cmdEl) cmdEl.textContent = "loading…";
  if (opsecEl) opsecEl.textContent = "";
  if (eventsEl) eventsEl.textContent = "";
  if (warningsEl) warningsEl.textContent = "";
  if (altsWrap) altsWrap.hidden = true;

  try {
    const res = await fetch(`/api/v1/abuse?src=${encodeURIComponent(e.source)}&kind=${encodeURIComponent(e.kind)}&dst=${encodeURIComponent(e.target)}`);
    const r = await res.json();
    if (!res.ok) throw new Error(r.error || res.statusText);
    if (cmdEl) cmdEl.textContent = r.command || "";
    if (opsecEl) opsecEl.textContent = r.opsec || "";
    if (eventsEl) eventsEl.textContent = (r.event_ids && r.event_ids.length) ? "Event IDs: " + r.event_ids.join(", ") : "";
    if (warningsEl) warningsEl.textContent = (r.warnings && r.warnings.length) ? "⚠ " + r.warnings.join("; ") : "";
    if (r.alternates && r.alternates.length && altsWrap && altsEl) {
      altsWrap.hidden = false;
      altsEl.textContent = r.alternates.join("\n");
    }
  } catch (err) {
    if (cmdEl) cmdEl.textContent = "error: " + err.message;
  }
}

function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

// search highlight (dim non-matching)
const searchEl = document.getElementById("search");
if (searchEl) {
  let debounceTimer = null;
  searchEl.addEventListener("input", (ev) => {
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(() => {
      const q = ev.target.value.trim().toLowerCase();
      const clearBtn = document.getElementById("searchClear");
      if (clearBtn) clearBtn.hidden = q === "";
      for (const n of nodes) {
        const hay = `${n.name || ""} ${n.sam_account_name || ""} ${n.id}`.toLowerCase();
        n.dim = q !== "" && !hay.includes(q);
      }
      draw();
    }, 150);
  });
  // Clear search
  const clearBtn = document.getElementById("searchClear");
  if (clearBtn) {
    clearBtn.addEventListener("click", () => {
      searchEl.value = "";
      clearBtn.hidden = true;
      for (const n of nodes) n.dim = false;
      draw();
    });
  }
}
const reloadEl = document.getElementById("reload");
if (reloadEl) reloadEl.addEventListener("click", refresh);

// Toolbar controls
const fitViewBtn = document.getElementById("fitView");
if (fitViewBtn) fitViewBtn.addEventListener("click", fitView);

const resetViewBtn = document.getElementById("resetView");
if (resetViewBtn) resetViewBtn.addEventListener("click", resetView);

const centerSelectionBtn = document.getElementById("centerSelection");
if (centerSelectionBtn) centerSelectionBtn.addEventListener("click", centerSelection);

const showLabelsEl = document.getElementById("showLabels");
if (showLabelsEl) showLabelsEl.addEventListener("change", draw);

const showEdgeLabelsEl = document.getElementById("showEdgeLabels");
if (showEdgeLabelsEl) showEdgeLabelsEl.addEventListener("change", draw);

const showLegendEl = document.getElementById("showLegend");
const legendEl = document.getElementById("legend");
if (showLegendEl && legendEl) {
  showLegendEl.addEventListener("change", () => {
    legendEl.style.display = showLegendEl.checked ? "flex" : "none";
  });
}

const nodeKindFilter = document.getElementById("nodeKindFilter");
if (nodeKindFilter) nodeKindFilter.addEventListener("change", applyFilters);

const edgeKindFilter = document.getElementById("edgeKindFilter");
if (edgeKindFilter) edgeKindFilter.addEventListener("change", applyFilters);

function applyFilters() {
  const nodeKind = nodeKindFilter ? nodeKindFilter.value : "";
  const edgeKind = edgeKindFilter ? edgeKindFilter.value : "";
  // Filtering is handled by dimming in draw
  for (const n of nodes) {
    n.dim = (nodeKind && n.kind !== nodeKind);
  }
  // For edges, we could dim them too but for now just redraw
  draw();
}

function fitView() {
  if (nodes.length === 0) return;
  let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
  for (const n of nodes) {
    if (n.dim) continue;
    minX = Math.min(minX, n.x);
    minY = Math.min(minY, n.y);
    maxX = Math.max(maxX, n.x);
    maxY = Math.max(maxY, n.y);
  }
  if (!isFinite(minX)) return;
  const w = canvas.clientWidth, h = canvas.clientHeight;
  const cx = (minX + maxX) / 2;
  const cy = (minY + maxY) / 2;
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
    const mx = (a.x + b.x) / 2;
    const my = (a.y + b.y) / 2;
    const w = canvas.clientWidth, h = canvas.clientHeight;
    view.x = w / 2 - mx;
    view.y = h / 2 - my;
  }
}

// ---- write-API auth gate ----
let operatorToken = null;
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

const pushBtn = document.getElementById("push");
if (pushBtn) pushBtn.addEventListener("click", openGate);
const gateCancel = document.getElementById("gate-cancel");
if (gateCancel) gateCancel.addEventListener("click", closeGate);
if (gate) {
  gate.addEventListener("keydown", (ev) => { if (ev.key === "Escape") closeGate(); });
}

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
        headers: { "Content-Type": "application/json", "Authorization": "Bearer " + token },
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

// Copy buttons
const copyCommandBtn = document.getElementById("copyCommand");
if (copyCommandBtn) {
  copyCommandBtn.addEventListener("click", () => {
    const pre = document.getElementById("edge-command");
    if (pre) {
      navigator.clipboard.writeText(pre.textContent);
      copyCommandBtn.textContent = "✓";
      copyCommandBtn.classList.add("copied");
      setTimeout(() => {
        copyCommandBtn.textContent = "📋";
        copyCommandBtn.classList.remove("copied");
      }, 1500);
    }
  });
}

const copyAltsBtn = document.getElementById("copyAlts");
if (copyAltsBtn) {
  copyAltsBtn.addEventListener("click", () => {
    const pre = document.getElementById("edge-alts");
    if (pre) {
      navigator.clipboard.writeText(pre.textContent);
      copyAltsBtn.textContent = "✓";
      copyAltsBtn.classList.add("copied");
      setTimeout(() => {
        copyAltsBtn.textContent = "📋";
        copyAltsBtn.classList.remove("copied");
      }, 1500);
    }
  });
}

// Ingestion tab copy buttons
document.querySelectorAll('.copy-btn[data-target]').forEach(btn => {
  btn.addEventListener('click', () => {
    const target = document.getElementById(btn.dataset.target);
    if (target) {
      navigator.clipboard.writeText(target.textContent);
      btn.textContent = "✓";
      btn.classList.add("copied");
      setTimeout(() => {
        btn.textContent = "📋";
        btn.classList.remove("copied");
      }, 1500);
    }
  });
});

// Ingestion tabs
document.querySelectorAll('.ingestion-tabs .tab-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.ingestion-tabs .tab-btn').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.tab-panel').forEach(p => p.hidden = true);
    btn.classList.add('active');
    const panel = document.getElementById('tab-' + btn.dataset.tab);
    if (panel) panel.hidden = false;
  });
});

async function refresh() {
  try { await loadGraph(); } catch (e) {}
  try { await loadDomains(); } catch (e) {}
  try {
    const res = await fetch("/api/v1/health");
    if (res.ok) {
      const h = await res.json();
      const healthEl = document.getElementById("health");
      if (healthEl) {
        healthEl.textContent = `v${h.version} · credential-ops ${h.credential_ops_enabled ? "ON" : "off"} · write-api ${h.write_api_enabled ? "ON" : "off"}`;
        healthEl.className = "stats " + (h.write_api_enabled ? "success" : "muted");
      }
    } else {
      const healthEl = document.getElementById("health");
      if (healthEl) healthEl.textContent = `health: ${res.status}`;
    }
  } catch (e) {
    const healthEl = document.getElementById("health");
    if (healthEl) healthEl.textContent = "health: error";
  }
  setLock(!!operatorToken);
}

function init() {
  try { resize(); } catch (e) {}
  attachNav();
  setView('graph');
  refresh().then(() => {
    settleLayout();
    try { loop(); } catch (e) {}
  });
}

try { attachNav(); } catch(e){}
if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", init);
} else {
  init();
}

function setView(name) {
  document.querySelectorAll('.view').forEach(v => v.classList.toggle('active', v.id === 'view-' + name));
  document.querySelectorAll('.nav-btn').forEach(b => b.classList.toggle('active', b.dataset.view === name));
  if (name === 'graph') {
    // Force resize after view is visible
    setTimeout(() => { resize(); fitView(); }, 10);
  }
  try {
    if (name === 'domains') loadDomains();
    else if (name === 'users') loadUsers();
    else if (name === 'groups') loadGroups();
    else if (name === 'computers') loadComputers();
    else if (name === 'ous') loadOUs();
    else if (name === 'gpos') loadGPOs();
    else if (name === 'containers') loadContainers();
    else if (name === 'trusts') loadTrusts();
    else if (name === 'relationships') loadRelationships();
    else if (name === 'paths') loadPathOptions();
    else if (name === 'overview') loadOverview();
  } catch (e) {}
}

function attachNav() {
  document.querySelectorAll('.nav-btn').forEach(b => {
    b.removeEventListener('click', navClick);
    b.addEventListener('click', navClick);
  });
}
function navClick() {
  const view = this.dataset.view;
  if (view) setView(view);
}

// Sidebar toggle
const sidebarToggle = document.getElementById("sidebarToggle");
const sidebar = document.getElementById("sidebar");
if (sidebarToggle && sidebar) {
  sidebarToggle.addEventListener("click", () => {
    sidebar.classList.toggle("collapsed");
  });
}

// Mobile sidebar overlay
const overlay = document.createElement("div");
overlay.className = "sidebar-overlay";
document.body.appendChild(overlay);
overlay.addEventListener("click", () => {
  sidebar.classList.remove("open");
  overlay.classList.remove("visible");
});
// Add open class on mobile when sidebar is shown
if (window.innerWidth <= 768) {
  sidebarToggle.addEventListener("click", () => {
    sidebar.classList.toggle("open");
    overlay.classList.toggle("visible");
  });
}

async function loadDomains() {
  try {
    const r = await fetch('/api/v1/domains');
    const j = await r.json();
    const sel = document.getElementById('domainSelect');
    if (sel) {
      sel.innerHTML = '<option value="">All Domains</option>';
      (j.domains || []).forEach(d => {
        const opt = document.createElement('option');
        opt.value = d; opt.textContent = d; sel.appendChild(opt);
      });
    }
    // Also populate domain list view
    const list = document.getElementById('domainsList');
    if (list) {
      list.innerHTML = (j.domains || []).map(d => `<div class="list-item"><strong>${esc(d)}</strong></div>`).join('');
    }
  } catch(e) {}
}

async function loadObjects(type, opts = {}) {
  const params = new URLSearchParams();
  if (opts.domain) params.set('domain', opts.domain);
  if (opts.search) params.set('search', opts.search);
  if (type) params.set('type', type);
  params.set('limit', '100');
  if (opts.offset) params.set('offset', opts.offset);
  const r = await fetch('/api/v1/objects?' + params);
  return await r.json();
}

let currentDomain = '';

const domainSel = document.getElementById('domainSelect');
if (domainSel) {
  domainSel.addEventListener('change', e => {
    currentDomain = e.target.value;
    const active = document.querySelector('.nav-btn.active');
    const view = active ? active.dataset.view : '';
    if (view === 'users') loadUsers();
    if (view === 'groups') loadGroups();
    if (view === 'computers') loadComputers();
    if (view === 'ous') loadOUs();
    if (view === 'gpos') loadGPOs();
    if (view === 'containers') loadContainers();
  });
}

async function loadUsers() {
  const res = await loadObjects('User', {domain: currentDomain, search: document.getElementById('userSearch').value});
  const tbl = document.getElementById('usersTable');
  if (tbl) {
    tbl.innerHTML = '<thead><tr><th>Name</th><th>SAM</th><th>Domain</th><th>Enabled</th><th>SID</th></tr></thead><tbody>' +
      (res.nodes||[]).map(n => `<tr><td>${escapeHtml(n.name||'')}</td><td>${escapeHtml(n.sam_account_name||'')}</td><td>${escapeHtml(n.domain||'')}</td><td class="${n.props?.enabled === 'true' ? 'enabled' : 'disabled'}">${n.props?.enabled === 'true' ? 'Yes' : 'No'}</td><td>${escapeHtml(n.id||'')}</td></tr>`).join('') + '</tbody>';
  }
}
const userSearchEl = document.getElementById('userSearch');
if (userSearchEl) {
  let debounce = null;
  userSearchEl.addEventListener('input', () => {
    clearTimeout(debounce);
    debounce = setTimeout(loadUsers, 300);
  });
}

async function loadGroups() {
  const res = await loadObjects('Group', {domain: currentDomain, search: document.getElementById('groupSearch').value});
  const tbl = document.getElementById('groupsTable');
  if (tbl) {
    tbl.innerHTML = '<thead><tr><th>Name</th><th>Type</th><th>Domain</th><th>Members</th><th>SID</th></tr></thead><tbody>' +
      (res.nodes||[]).map(n => `<tr><td>${escapeHtml(n.name||'')}</td><td>${escapeHtml(n.props?.type||'')}</td><td>${escapeHtml(n.domain||'')}</td><td>${escapeHtml(n.props?.member_count||'')}</td><td>${escapeHtml(n.id||'')}</td></tr>`).join('') + '</tbody>';
  }
}
const groupSearchEl = document.getElementById('groupSearch');
if (groupSearchEl) {
  let debounce = null;
  groupSearchEl.addEventListener('input', () => {
    clearTimeout(debounce);
    debounce = setTimeout(loadGroups, 300);
  });
}

async function loadComputers() {
  const res = await loadObjects('Computer', {domain: currentDomain, search: document.getElementById('compSearch').value});
  const tbl = document.getElementById('compsTable');
  if (tbl) {
    tbl.innerHTML = '<thead><tr><th>Name</th><th>Domain</th><th>OS</th><th>SID</th></tr></thead><tbody>' +
      (res.nodes||[]).map(n => `<tr><td>${escapeHtml(n.name||'')}</td><td>${escapeHtml(n.domain||'')}</td><td>${escapeHtml(n.props?.os||'')}</td><td>${escapeHtml(n.id||'')}</td></tr>`).join('') + '</tbody>';
  }
}
const compSearchEl = document.getElementById('compSearch');
if (compSearchEl) {
  let debounce = null;
  compSearchEl.addEventListener('input', () => {
    clearTimeout(debounce);
    debounce = setTimeout(loadComputers, 300);
  });
}

async function loadOUs() {
  const res = await loadObjects('OU', {domain: currentDomain, search: document.getElementById('ouSearch').value});
  const tbl = document.getElementById('ousTable');
  if (tbl) {
    tbl.innerHTML = '<thead><tr><th>Name</th><th>Domain</th><th>Distinguished Name</th><th>SID</th></tr></thead><tbody>' +
      (res.nodes||[]).map(n => `<tr><td>${escapeHtml(n.name||'')}</td><td>${escapeHtml(n.domain||'')}</td><td>${escapeHtml(n.distinguished_name||'')}</td><td>${escapeHtml(n.id||'')}</td></tr>`).join('') + '</tbody>';
  }
}
const ouSearchEl = document.getElementById('ouSearch');
if (ouSearchEl) {
  let debounce = null;
  ouSearchEl.addEventListener('input', () => {
    clearTimeout(debounce);
    debounce = setTimeout(loadOUs, 300);
  });
}

async function loadGPOs() {
  const res = await loadObjects('GPO', {domain: currentDomain, search: document.getElementById('gpoSearch').value});
  const tbl = document.getElementById('gposTable');
  if (tbl) {
    tbl.innerHTML = '<thead><tr><th>Name</th><th>Domain</th><th>GUID</th><th>SID</th></tr></thead><tbody>' +
      (res.nodes||[]).map(n => `<tr><td>${escapeHtml(n.name||'')}</td><td>${escapeHtml(n.domain||'')}</td><td>${escapeHtml(n.props?.guid||'')}</td><td>${escapeHtml(n.id||'')}</td></tr>`).join('') + '</tbody>';
  }
}
const gpoSearchEl = document.getElementById('gpoSearch');
if (gpoSearchEl) {
  let debounce = null;
  gpoSearchEl.addEventListener('input', () => {
    clearTimeout(debounce);
    debounce = setTimeout(loadGPOs, 300);
  });
}

async function loadContainers() {
  const res = await loadObjects('Container', {domain: currentDomain, search: document.getElementById('containerSearch').value});
  const tbl = document.getElementById('containersTable');
  if (tbl) {
    tbl.innerHTML = '<thead><tr><th>Name</th><th>Domain</th><th>Distinguished Name</th><th>SID</th></tr></thead><tbody>' +
      (res.nodes||[]).map(n => `<tr><td>${escapeHtml(n.name||'')}</td><td>${escapeHtml(n.domain||'')}</td><td>${escapeHtml(n.distinguished_name||'')}</td><td>${escapeHtml(n.id||'')}</td></tr>`).join('') + '</tbody>';
  }
}
const containerSearchEl = document.getElementById('containerSearch');
if (containerSearchEl) {
  let debounce = null;
  containerSearchEl.addEventListener('input', () => {
    clearTimeout(debounce);
    debounce = setTimeout(loadContainers, 300);
  });
}

async function loadTrusts() {
  try {
    const r = await fetch('/api/v1/trusts');
    const j = await r.json();
    const tbl = document.getElementById('trustsTable');
    if (tbl) {
      tbl.innerHTML = '<thead><tr><th>Source Domain</th><th>Target Domain</th><th>Type</th><th>Transitive</th><th>SID Filtering</th></tr></thead><tbody>' +
        (j.trusts||[]).map(t => `<tr><td>${escapeHtml(t.source||'')}</td><td>${escapeHtml(t.target||'')}</td><td>${escapeHtml(t.type||'')}</td><td>${t.transitive ? 'Yes' : 'No'}</td><td>${t.sid_filtering ? 'Yes' : 'No'}</td></tr>`).join('') + '</tbody>';
    }
  } catch(e) {}
}

async function loadRelationships() {
  try {
    const r = await fetch('/api/v1/edges');
    const j = await r.json();
    const tbl = document.getElementById('relsTable');
    if (tbl) {
      tbl.innerHTML = '<thead><tr><th>Type</th><th>Source</th><th>Target</th><th>Properties</th></tr></thead><tbody>' +
        (j.edges||[]).map(e => `<tr><td>${escapeHtml(e.kind||'')}</td><td>${escapeHtml(e.source||'')}</td><td>${escapeHtml(e.target||'')}</td><td>${escapeHtml(JSON.stringify(e.props||{}))}</td></tr>`).join('') + '</tbody>';
    }
  } catch(e) {}
}

async function loadPathOptions() {
  // Populate node type and relationship type multi-selects
  const kinds = [...new Set(nodes.map(n => n.kind))].sort();
  const relTypes = [...new Set(edges.map(e => e.kind))].sort();

  const includeNodes = document.getElementById('pathIncludeNodes');
  const excludeNodes = document.getElementById('pathExcludeNodes');
  const includeRels = document.getElementById('pathIncludeRels');
  const excludeRels = document.getElementById('pathExcludeRels');

  const nodeOptions = kinds.map(k => `<option value="${esc(k)}">${k}</option>`).join('');
  const relOptions = relTypes.map(k => `<option value="${esc(k)}">${k}</option>`).join('');

  if (includeNodes) includeNodes.innerHTML = nodeOptions;
  if (excludeNodes) excludeNodes.innerHTML = nodeOptions;
  if (includeRels) includeRels.innerHTML = relOptions;
  if (excludeRels) excludeRels.innerHTML = relOptions;
}

function escapeHtml(s) {
  if (s == null) return '';
  return String(s).replace(/[&<>"']/g, m => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#039;'}[m]));
}

async function searchForPath(id, q, cb) {
  if (!q || q.length < 2) { cb([]); return; }
  const params = new URLSearchParams();
  params.set('search', q);
  params.set('limit', '20');
  const r = await fetch('/api/v1/objects?' + params);
  const j = await r.json();
  cb(j.nodes || []);
}

let pathSrcSel = null, pathDstSel = null;
const pathSrcEl = document.getElementById('pathSrc');
if (pathSrcEl) {
  let debounce = null;
  pathSrcEl.addEventListener('input', async e => {
    clearTimeout(debounce);
    debounce = setTimeout(async () => {
      const q = e.target.value;
      if (!q || q.length < 2) { document.getElementById('pathSrcRes').innerHTML = ''; return; }
      const params = new URLSearchParams();
      params.set('search', q);
      params.set('limit', '10');
      const r = await fetch('/api/v1/objects?' + params);
      const res = await r.json();
      const el = document.getElementById('pathSrcRes'); el.innerHTML = '';
      (res.nodes || []).forEach(n => {
        const d = document.createElement('div'); d.className = 'suggest-item'; d.textContent = (n.name || n.sam_account_name || n.id) + ' (' + n.kind + ')'; d.onclick = () => { document.getElementById('pathSrc').value = d.textContent; pathSrcSel = n.id; el.innerHTML = ''; };
        el.appendChild(d);
      });
    }, 200);
  });
}

const pathDstEl = document.getElementById('pathDst');
if (pathDstEl) {
  let debounce = null;
  pathDstEl.addEventListener('input', async e => {
    clearTimeout(debounce);
    debounce = setTimeout(async () => {
      const q = e.target.value;
      if (!q || q.length < 2) { document.getElementById('pathDstRes').innerHTML = ''; return; }
      const params = new URLSearchParams();
      params.set('search', q);
      params.set('limit', '10');
      const r = await fetch('/api/v1/objects?' + params);
      const res = await r.json();
      const el = document.getElementById('pathDstRes'); el.innerHTML = '';
      (res.nodes || []).forEach(n => { const d = document.createElement('div'); d.className = 'suggest-item'; d.textContent = (n.name || n.sam_account_name || n.id) + ' (' + n.kind + ')'; d.onclick = () => { document.getElementById('pathDst').value = d.textContent; pathDstSel = n.id; el.innerHTML = ''; }; el.appendChild(d); });
    }, 200);
  });
}

const pathSearchBtn = document.getElementById('pathSearch');
if (pathSearchBtn) {
  pathSearchBtn.addEventListener('click', async () => {
    if (!pathSrcSel || !pathDstSel) return;
    const body = {
      source_id: pathSrcSel,
      target_id: pathDstSel,
      max_depth: parseInt(document.getElementById('pathDepth').value || '5'),
      max_paths: parseInt(document.getElementById('pathMax').value || '10'),
      direction: document.getElementById('pathDir').value,
      include_node_types: Array.from(document.getElementById('pathIncludeNodes').selectedOptions).map(o => o.value),
      exclude_node_types: Array.from(document.getElementById('pathExcludeNodes').selectedOptions).map(o => o.value),
      include_relationship_types: Array.from(document.getElementById('pathIncludeRels').selectedOptions).map(o => o.value),
      exclude_relationship_types: Array.from(document.getElementById('pathExcludeRels').selectedOptions).map(o => o.value),
    };
    const r = await fetch('/api/v1/paths/shortest', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    const j = await r.json();
    const el = document.getElementById('pathResults'); el.innerHTML = '';
    (j.paths || []).forEach((p, i) => {
      const div = document.createElement('div'); div.className = 'path-item';
      div.innerHTML = '<strong>Path ' + (i+1) + ' (len=' + p.length + ')</strong><br/>' +
        (p.nodes || []).map(n => n.name || n.id).join(' → ') + '<br/>' +
        (p.relationships || []).map(e => e.kind).join(' · ');
      el.appendChild(div);
    });
  });
}

const pathClearBtn = document.getElementById('pathClear');
if (pathClearBtn) {
  pathClearBtn.addEventListener('click', () => {
    document.getElementById('pathSrc').value = '';
    document.getElementById('pathDst').value = '';
    document.getElementById('pathResults').innerHTML = '';
    pathSrcSel = null; pathDstSel = null;
  });
}

// Ingestion form
const ingestSubmit = document.getElementById('ingestSubmit');
if (ingestSubmit) {
  ingestSubmit.addEventListener('click', async () => {
    const fileEl = document.getElementById('ingestFile');
    const tokenEl = document.getElementById('ingestToken');
    const statusEl = document.getElementById('ingestStatus');
    const file = fileEl?.files?.[0];
    const token = tokenEl?.value?.trim();
    if (!file || !token) {
      if (statusEl) { statusEl.textContent = "Select a file and provide token"; statusEl.className = "warn"; }
      return;
    }
    if (statusEl) { statusEl.textContent = "Uploading…"; statusEl.className = "muted"; }
    const text = await file.text();
    try {
      const res = await fetch("/api/v1/ingest", {
        method: "POST",
        headers: { "Content-Type": "application/json", "Authorization": "Bearer " + token },
        body: text,
      });
      const r = await res.json();
      if (!res.ok) throw new Error(r.error || res.statusText);
      if (statusEl) { statusEl.textContent = `OK: ${r.nodes} nodes, ${r.edges} edges ingested`; statusEl.className = "success"; }
      await refresh();
    } catch (err) {
      if (statusEl) { statusEl.textContent = "Error: " + err.message; statusEl.className = "warn"; }
    }
  });
}

// Audit refresh
const auditRefresh = document.getElementById('auditRefresh');
if (auditRefresh) {
  auditRefresh.addEventListener('click', async () => {
    const limit = document.getElementById('auditLimit').value;
    const r = await fetch('/api/v1/audit?limit=' + limit);
    const j = await r.json();
    const tbl = document.getElementById('auditTable');
    if (tbl) {
      tbl.innerHTML = '<thead><tr><th>Time</th><th>Actor</th><th>Action</th><th>Target</th><th>Result</th><th>Reason</th></tr></thead><tbody>' +
        (j.events||[]).map(e => `<tr><td>${escapeHtml(e.time||'')}</td><td>${escapeHtml(e.actor||'')}</td><td>${escapeHtml(e.action||'')}</td><td>${escapeHtml(e.target||'')}</td><td>${escapeHtml(e.result||'')}</td><td>${escapeHtml(e.reason||'')}</td></tr>`).join('') + '</tbody>';
    }
  });
}

// Settings
function loadSettings() {
  // Load from localStorage
  const settings = JSON.parse(localStorage.getItem('omenhound-settings') || '{}');
  document.getElementById('settingLabels')?.checked = settings.labels !== false;
  document.getElementById('settingEdgeLabels')?.checked = settings.edgeLabels === true;
  document.getElementById('settingLegend')?.checked = settings.legend !== false;
  document.getElementById('settingPhysics')?.checked = settings.physics !== false;
  document.getElementById('settingReduceMotion')?.checked = settings.reduceMotion === true;
  document.getElementById('settingAutoRefresh')?.checked = settings.autoRefresh !== false;
  document.getElementById('settingPreserveSelection')?.checked = settings.preserveSelection !== false;
  document.getElementById('settingRefreshInterval')?.value = settings.refreshInterval || 0;
  document.getElementById('settingTheme')?.value = settings.theme || 'dark';
  document.getElementById('settingDensity')?.value = settings.density || 'comfortable';
  applySettings(settings);
}

function saveSettings() {
  const settings = {
    labels: document.getElementById('settingLabels')?.checked,
    edgeLabels: document.getElementById('settingEdgeLabels')?.checked,
    legend: document.getElementById('settingLegend')?.checked,
    physics: document.getElementById('settingPhysics')?.checked,
    reduceMotion: document.getElementById('settingReduceMotion')?.checked,
    autoRefresh: document.getElementById('settingAutoRefresh')?.checked,
    preserveSelection: document.getElementById('settingPreserveSelection')?.checked,
    refreshInterval: parseInt(document.getElementById('settingRefreshInterval')?.value || '0'),
    theme: document.getElementById('settingTheme')?.value,
    density: document.getElementById('settingDensity')?.value,
  };
  localStorage.setItem('omenhound-settings', JSON.stringify(settings));
  applySettings(settings);
}

function applySettings(settings) {
  // Apply theme
  document.documentElement.setAttribute('data-theme', settings.theme);
  // Apply density
  document.body.classList.remove('density-compact', 'density-comfortable', 'density-spacious');
  document.body.classList.add('density-' + settings.density);
  // Apply reduce motion
  if (settings.reduceMotion) {
    document.body.classList.add('reduce-motion');
  } else {
    document.body.classList.remove('reduce-motion');
  }
  // Apply labels
  if (document.getElementById('showLabels')) {
    document.getElementById('showLabels').checked = settings.labels;
  }
  if (document.getElementById('showEdgeLabels')) {
    document.getElementById('showEdgeLabels').checked = settings.edgeLabels;
  }
  if (document.getElementById('showLegend')) {
    document.getElementById('showLegend').checked = settings.legend;
  }
  draw();
}

['settingLabels', 'settingEdgeLabels', 'settingLegend', 'settingPhysics', 'settingReduceMotion', 'settingAutoRefresh', 'settingPreserveSelection', 'settingRefreshInterval', 'settingTheme', 'settingDensity'].forEach(id => {
  const el = document.getElementById(id);
  if (el) el.addEventListener('change', saveSettings);
});

async function loadOverview() {
  try {
    const r = await fetch('/api/v1/stats');
    const s = await r.json();
    // Compute kinds from already-loaded nodes
    const kindCounts = {};
    for (const n of nodes) {
      kindCounts[n.kind] = (kindCounts[n.kind] || 0) + 1;
    }
    const grid = document.getElementById('overviewGrid');
    if (grid) {
      grid.innerHTML = [
        { label: 'Nodes', value: s.nodes, cls: 'edge' },
        { label: 'Edges', value: s.edges, cls: 'edge' },
        { label: 'Users', value: kindCounts.User || 0, cls: 'user' },
        { label: 'Groups', value: kindCounts.Group || 0, cls: 'group' },
        { label: 'Computers', value: kindCounts.Computer || 0, cls: 'computer' },
        { label: 'Domains', value: kindCounts.Domain || 0, cls: 'domain' },
        { label: 'OUs', value: kindCounts.OU || 0, cls: 'ou' },
        { label: 'GPOs', value: kindCounts.GPO || 0, cls: 'gpo' },
        { label: 'Containers', value: kindCounts.Container || 0, cls: 'container' },
        { label: 'Trusts', value: kindCounts.Trust || 0, cls: 'trust' },
      ].map(stat => `<div class="stat-card ${stat.cls}"><div class="icon">${stat.cls === 'edge' ? '⛶' : stat.cls[0]}</div><div class="value">${stat.value}</div><div class="label">${stat.label}</div></div>`).join('');
    }
  } catch (e) {}
}

// Ingest file input
const ingestFileEl = document.getElementById('ingestFile');
if (ingestFileEl) {
  ingestFileEl.addEventListener('change', () => {
    const file = ingestFileEl.files[0];
    if (file) {
      const statusEl = document.getElementById('ingestStatus');
      if (statusEl) { statusEl.textContent = `Selected: ${file.name} (${Math.round(file.size/1024)} KB)`; statusEl.className = "muted"; }
    }
  });
}

// Initialize settings
loadSettings();

// Initialize version
const versionDisplay = document.getElementById('versionDisplay');
if (versionDisplay) {
  fetch('/api/v1/health').then(r => r.json()).then(h => { versionDisplay.textContent = h.version; });
}

// Keyboard shortcuts
document.addEventListener('keydown', (e) => {
  if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA' || e.target.tagName === 'SELECT') return;
  switch(e.key) {
    case 'f': fitView(); break;
    case 'r': resetView(); break;
    case 'c': centerSelection(); break;
    case 'Escape':
      if (!gate?.hidden) closeGate();
      if (sidebar?.classList.contains('open')) {
        sidebar.classList.remove('open');
        overlay.classList.remove('visible');
      }
      break;
  }
});

// Global search - click result to focus in graph
async function globalSearch() {
  const q = searchEl?.value?.trim();
  if (!q || q.length < 2) return;
  const params = new URLSearchParams();
  params.set('search', q);
  params.set('limit', '20');
  const r = await fetch('/api/v1/objects?' + params);
  const j = await r.json();
  if (j.nodes?.length) {
    // Select first match
    const n = j.nodes[0];
    const match = nodes.find(node => node.id === n.id);
    if (match) {
      selectNode(match);
      centerSelection();
    }
  }
}

let searchDebounce = null;
if (searchEl) {
  searchEl.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      globalSearch();
    }
  });
}
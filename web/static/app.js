"use strict";

// OmenHound UI — dependency-free force-directed graph on a canvas.
// No CDN: works fully offline and ships inside the Go binary.

const COLORS = {
  User: "#7aa2ff",
  Group: "#57e0b0",
  Computer: "#ffb454",
  Domain: "#ff6b6b",
  GPO: "#c88cff",
  OU: "#9aa4b2",
  Container: "#6b7280",
  Trust: "#f06ea9",
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
  const r = canvas.parentElement.getBoundingClientRect();
  canvas.width = canvas.clientWidth * devicePixelRatio;
  canvas.height = canvas.clientHeight * devicePixelRatio;
  ctx.setTransform(devicePixelRatio, 0, 0, devicePixelRatio, 0, 0);
}
window.addEventListener("resize", resize);

function toScreen(p) {
  return { x: p.x * view.k + view.x, y: p.y * view.k + view.y };
}
function toWorld(sx, sy) {
  return { x: (sx - view.x) / view.k, y: (sy - view.y) / view.k };
}

async function loadGraph() {
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
  document.getElementById("stats").textContent = `${nodes.length} nodes · ${edges.length} edges`;
  renderLegend();
}

function renderLegend() {
  const kinds = [...new Set(nodes.map((n) => n.kind))].sort();
  document.getElementById("legend").innerHTML =
    kinds.map((k) => `<span><i style="background:${COLORS[k] || "#888"}"></i>${k}</span>`).join("");
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
  const w = canvas.clientWidth, h = canvas.clientHeight;
  ctx.clearRect(0, 0, w, h);

  // edges
  ctx.lineWidth = 1.2;
  for (const e of edges) {
    const a = toScreen(byId.get(e.source));
    const b = toScreen(byId.get(e.target));
    const sel = selectedEdge && selectedEdge.source === e.source && selectedEdge.target === e.target && selectedEdge.kind === e.kind;
    ctx.strokeStyle = sel ? "#57e0b0" : "rgba(140,152,178,0.35)";
    ctx.beginPath();
    ctx.moveTo(a.x, a.y);
    ctx.lineTo(b.x, b.y);
    ctx.stroke();
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

// ---- interaction ----

function hitNode(sx, sy) {
  let best = null, bestD = 14;
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
  let best = null, bestD = 6;
  for (const e of edges) {
    const a = toScreen(byId.get(e.source));
    const b = toScreen(byId.get(e.target));
    const d = distToSeg(sx, sy, a.x, a.y, b.x, b.y);
    if (d < bestD) { bestD = d; best = e; }
  }
  return best;
}

canvas.addEventListener("mousedown", (ev) => {
  const sx = ev.offsetX, sy = ev.offsetY;
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
  const sx = ev.offsetX, sy = ev.offsetY;
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
  const sx = ev.offsetX, sy = ev.offsetY;
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
  const sx = ev.offsetX, sy = ev.offsetY;
  const before = toWorld(sx, sy);
  const factor = ev.deltaY < 0 ? 1.12 : 1 / 1.12;
  view.k = Math.max(0.15, Math.min(4, view.k * factor));
  const after = toWorld(sx, sy);
  view.x += (after.x - before.x) * view.k;
  view.y += (after.y - before.y) * view.k;
}, { passive: false });

// ---- panels ----

function show(id) {
  for (const s of ["panel-empty", "panel-node", "panel-edge"]) {
    document.getElementById(s).hidden = s !== id;
  }
}

function selectNode(n) {
  selectedNode = n;
  selectedEdge = null;
  show("panel-node");
  document.getElementById("node-title").textContent = n.name || n.sam_account_name || n.id;
  const rows = [
    ["kind", n.kind],
    ["sid", n.id],
    ["sam", n.sam_account_name || ""],
    ["domain", n.domain || ""],
    ["dn", n.distinguished_name || ""],
    ...Object.entries(n.props || {}),
  ].filter(([, v]) => v !== "" && v !== undefined);
  document.getElementById("node-props").innerHTML = rows
    .map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(String(v))}</dd>`)
    .join("");

  const out = edges.filter((e) => e.source === n.id);
  const inc = edges.filter((e) => e.target === n.id);
  document.getElementById("node-out").innerHTML = edgeList(out, "target");
  document.getElementById("node-in").innerHTML = edgeList(inc, "source");
  for (const li of document.querySelectorAll("#node-out li,#node-in li")) {
    li.addEventListener("click", () => {
      const e = edges.find((x) => x.source === li.dataset.src && x.target === li.dataset.tgt && x.kind === li.dataset.kind);
      if (e) selectEdge(e);
    });
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
  document.getElementById("edge-title").textContent = `${e.kind}`;
  document.getElementById("edge-summary").textContent =
    `${a ? a.name || a.id : e.source} → ${b ? b.name || b.id : e.target}`;
  document.getElementById("edge-command").textContent = "loading…";
  document.getElementById("edge-opsec").textContent = "";
  document.getElementById("edge-events").textContent = "";
  document.getElementById("edge-warnings").textContent = "";
  document.getElementById("edge-alts-wrap").hidden = true;

  try {
    const res = await fetch(`/api/v1/abuse?src=${encodeURIComponent(e.source)}&kind=${encodeURIComponent(e.kind)}&dst=${encodeURIComponent(e.target)}`);
    const r = await res.json();
    if (!res.ok) throw new Error(r.error || res.statusText);
    document.getElementById("edge-command").textContent = r.command || "";
    document.getElementById("edge-opsec").textContent = r.opsec || "";
    document.getElementById("edge-events").textContent =
      (r.event_ids && r.event_ids.length) ? "Event IDs: " + r.event_ids.join(", ") : "";
    document.getElementById("edge-warnings").textContent =
      (r.warnings && r.warnings.length) ? "⚠ " + r.warnings.join("; ") : "";
    if (r.alternates && r.alternates.length) {
      document.getElementById("edge-alts-wrap").hidden = false;
      document.getElementById("edge-alts").textContent = r.alternates.join("\n");
    }
  } catch (err) {
    document.getElementById("edge-command").textContent = "error: " + err.message;
  }
}

function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

// search highlight (dim non-matching)
document.getElementById("search").addEventListener("input", (ev) => {
  const q = ev.target.value.trim().toLowerCase();
  for (const n of nodes) {
    const hay = `${n.name || ""} ${n.sam_account_name || ""} ${n.id}`.toLowerCase();
    n.dim = q !== "" && !hay.includes(q);
  }
  draw();
});
document.getElementById("reload").addEventListener("click", refresh);

async function refresh() {
  await loadGraph();
  const res = await fetch("/api/v1/health");
  const h = await res.json();
  document.getElementById("health").textContent =
    `v${h.version} · credential-ops ${h.credential_ops_enabled ? "ON" : "off"} · write-api ${h.write_api_enabled ? "ON" : "off"}`;
}

resize();
refresh().then(loop);
